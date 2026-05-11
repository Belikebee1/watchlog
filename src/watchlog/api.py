"""REST API daemon — FastAPI app exposing watchlog state and actions over HTTP.

Endpoints:
    GET  /                          Dashboard SPA (HTML)
    GET  /api/v1                    API metadata
    GET  /api/v1/health             Public liveness
    POST /api/v1/pair               Exchange pairing code for per-device token
                                    (rate-limited, no auth required)
    GET  /api/v1/status             Latest heartbeat (status.json)
    GET  /api/v1/reports            List recent run archives
    GET  /api/v1/reports/{date}     Runs for a specific day (YYYY-MM-DD)
    POST /api/v1/runs               Trigger a fresh `watchlog run`
    GET  /api/v1/state              Snooze + ignore registry
    POST /api/v1/state/snooze       Body: {check, hours}
    POST /api/v1/state/ignore       Body: {check}
    DELETE /api/v1/state/snooze/{check}
    DELETE /api/v1/state/ignore/{check}
    POST /api/v1/actions/apply-security    Run unattended-upgrade
    POST /api/v1/push/register      Register FCM token for this device
    DELETE /api/v1/push/register/{token}

Authentication: every protected endpoint accepts a Bearer token. Tokens
come from two places:

  1. The legacy `api.token` in /etc/watchlog/config.yaml — treated as the
     "admin" / master token with full scopes. Cannot be revoked through the
     API; only by editing the config and restarting.

  2. Per-device tokens issued by `POST /api/v1/pair` (created via
     `watchlog api qr` on the server). Each lives in tokens.json with a
     SHA-256 hash; the plaintext is shown ONCE at issuance and never
     persisted. Revocable via `watchlog api tokens revoke <id>`.

Scopes (per-device tokens only): `read`, `act`, `push`. The admin token
implicitly has every scope.
"""

from __future__ import annotations

import json
import logging
import secrets
import shlex
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from fastapi import Depends, FastAPI, HTTPException, Path as FPath, Request, status
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "watchlog[api] extras not installed. Run: pip install 'watchlog[api]'"
    ) from exc

try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "slowapi missing — pip install 'watchlog[api]'"
    ) from exc

from watchlog import __version__
from watchlog.auth import (
    ALL_SCOPES,
    PAIRING_DEFAULT_TTL_SECONDS,
    PairingError,
    PairingStore,
    TokenStore,
    audit,
)
from watchlog.check_info import CHECK_INFO, SEVERITY_LEGEND
from watchlog.core.config import Config
from watchlog.fcm import TokenRegistry
from watchlog.host_info import collect_host_info
from watchlog.state import State

log = logging.getLogger(__name__)

DASHBOARD_DIR = Path(__file__).parent / "dashboard"
SECURITY = HTTPBearer(auto_error=False)


# --------------- Pydantic models ---------------


class HealthResponse(BaseModel):
    ok: bool = True
    version: str
    uptime_hint: str = "Use /api/v1/status to see when watchlog last ran."


class APIMeta(BaseModel):
    name: str = "watchlog"
    version: str
    docs: str = "/docs"


class SnoozeRequest(BaseModel):
    check: str = Field(..., description="Check name to snooze, e.g. 'ssl_certs'")
    hours: int = Field(4, ge=1, le=24 * 30, description="Hours to snooze (1..720)")


class IgnoreRequest(BaseModel):
    check: str = Field(..., description="Check name to ignore until manual clear")


class PushRegisterRequest(BaseModel):
    token: str = Field(..., description="FCM device token from Firebase")
    platform: str = Field("unknown", description="android | ios | unknown")
    device_label: str | None = Field(
        None, description="Optional human label, e.g. 'Andrzej iPhone'"
    )


class NotificationPreferencesPayload(BaseModel):
    """Per-device notification preferences. Every field is optional;
    omitted fields keep their previous value (PATCH semantics)."""

    quiet_hours_enabled: bool | None = Field(
        None,
        description="Master switch for the quiet window.",
    )
    quiet_start: str | None = Field(
        None,
        pattern=r"^([01]?\d|2[0-3]):[0-5]\d$",
        description="Local 24h start time, HH:MM.",
    )
    quiet_end: str | None = Field(
        None,
        pattern=r"^([01]?\d|2[0-3]):[0-5]\d$",
        description="Local 24h end time, HH:MM.",
    )
    quiet_timezone: str | None = Field(
        None,
        max_length=64,
        description="IANA tz name the device's quiet window is anchored to.",
    )
    quiet_min_severity: str | None = Field(
        None,
        pattern=r"^(OK|INFO|WARN|CRITICAL)$",
        description="Minimum severity that bypasses quiet hours. Default CRITICAL.",
    )
    min_severity: str | None = Field(
        None,
        pattern=r"^(OK|INFO|WARN|CRITICAL)$",
        description="Global floor — alerts below this never push.",
    )
    disabled_checks: list[str] | None = Field(
        None,
        max_length=64,
        description="Checks to mute. If every actionable check in a run "
                    "is on this list, the device gets no push.",
    )
    cooldown_hours: int | None = Field(
        None,
        ge=0,
        le=168,
        description="Smart grouping window: a (check, severity) combo "
                    "won't push twice within this many hours. 0 disables.",
    )


class PairRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Pairing code from `watchlog api qr` (case-insensitive)",
    )
    device_label: str | None = Field(
        None,
        max_length=100,
        description="Human-readable device name shown in `watchlog api tokens list`",
    )
    platform: str | None = Field(
        None,
        max_length=20,
        description="android | ios | other",
    )


class PairResponse(BaseModel):
    token: str = Field(..., description="The plaintext API token — store securely, never sent again")
    device_id: str = Field(..., description="Stable identifier for revocation via `watchlog api tokens revoke`")
    name: str = Field(..., description="Suggested display name for this server (hostname-derived)")
    scopes: list[str] = Field(..., description="Granted scopes: read | act | push")


class ActionResult(BaseModel):
    ok: bool
    exit_code: int
    output: str = Field(..., description="Combined stdout+stderr (last 8 KB)")
    command: str


class RestartServiceRequest(BaseModel):
    service: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._@-]+$",
        description="systemd unit name. Must be on the actions.allowed_services whitelist.",
    )


class TailLogsRequest(BaseModel):
    service: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._@-]+$",
        description="systemd unit name (whitelisted) or 'system' for the journal.",
    )
    lines: int = Field(
        100,
        ge=10,
        le=2000,
        description="How many recent journal lines to return.",
    )


class ActionDescriptor(BaseModel):
    """Metadata for one action shortcut available to clients. The
    mobile UI iterates these to render its actions panel; ops can
    add/remove without redeploying the app."""

    kind: str = Field(..., description="restart_service | reboot | tail_logs")
    target: str = Field(..., description="systemd unit name, or 'host' for reboot")
    label: str = Field(..., description="Human-readable label")
    destructive: bool = Field(
        False,
        description="UI hint — show in red and require extra confirmation.",
    )


# --------------- App factory ---------------


def create_app(config: Config) -> FastAPI:
    """Build a FastAPI app bound to the given config.

    Authentication accepts both:
      * the legacy `api.token` from /etc/watchlog/config.yaml (master/admin)
      * any non-revoked per-device token from /var/lib/watchlog/tokens.json,
        granted scope-by-scope as configured at issuance time

    If neither token source has any entries, the API runs open (only
    /api/v1/health and / are exposed; everything else 401s). This is a
    safety net during initial install, not a feature — the CLI bootstraps
    a master token on first run.
    """
    api_cfg = config.get("api", default={}) or {}
    admin_token: str = (api_cfg.get("token") if isinstance(api_cfg, dict) else "") or ""
    token_store = TokenStore()
    pairing_store = PairingStore()

    # Suggested display name for the server, returned alongside paired
    # tokens so the mobile app can pre-fill its label field.
    server_display_name = _server_display_name(config)

    limiter = Limiter(key_func=get_remote_address)

    app = FastAPI(
        title="watchlog API",
        version=__version__,
        description=(
            "REST API for the watchlog server health monitor. "
            "Most endpoints require Bearer authentication. Use "
            "`POST /api/v1/pair` with a code from `watchlog api qr` to "
            "obtain a per-device token."
        ),
        docs_url="/docs",
        redoc_url=None,
    )

    # Wire SlowAPI's rate-limit error handler so 429s come back as JSON
    # rather than the default plain text.
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please slow down."},
        )

    # --------------- auth dependency ---------------

    def _verify_bearer(
        request: Request,
        creds: HTTPAuthorizationCredentials | None,
        required_scope: str,
    ) -> None:
        # Open mode — only when neither admin token nor any per-device tokens
        # are configured. Lets `watchlog api setup` work during bootstrap.
        if not admin_token and not token_store.list_active():
            return

        if creds is None or creds.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        presented = creds.credentials

        # Admin token: constant-time compare against the configured master.
        # Implicitly has every scope, never logs to "last used" since it's
        # a static secret on disk.
        if admin_token and secrets.compare_digest(presented, admin_token):
            return

        # Per-device token: hash and look up. Lookup is constant-time per
        # candidate; total work is O(n) over registry size, which is fine
        # at the expected scale (handful of devices).
        record = token_store.find_by_token(presented)
        if record is None:
            audit(
                "TOKEN_AUTH_FAILED",
                ip=_client_ip(request),
                path=request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        scopes = record.get("scopes") or []
        if required_scope not in scopes:
            audit(
                "TOKEN_FORBIDDEN",
                token_id=record.get("id"),
                required=required_scope,
                granted=scopes,
                path=request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token missing scope: {required_scope}",
            )

        # Best-effort touch — never blocks request on file write.
        try:
            token_store.touch(record["id"], _client_ip(request))
        except Exception as exc:  # noqa: BLE001
            log.debug("touch failed: %s", exc)

    def require_read(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> None:
        _verify_bearer(request, creds, "read")

    def require_act(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> None:
        _verify_bearer(request, creds, "act")

    def require_push(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> None:
        _verify_bearer(request, creds, "push")

    # --------------- public endpoints ---------------

    @app.get("/", include_in_schema=False)
    def dashboard_root() -> FileResponse:
        index = DASHBOARD_DIR / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=404, detail="Dashboard not built")
        return FileResponse(index)

    if DASHBOARD_DIR.is_dir():
        app.mount(
            "/static",
            StaticFiles(directory=str(DASHBOARD_DIR)),
            name="static",
        )

    @app.get("/api/v1", response_model=APIMeta, tags=["meta"])
    def api_root() -> APIMeta:
        return APIMeta(version=__version__)

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["meta"])
    def healthz() -> HealthResponse:
        return HealthResponse(version=__version__)

    # --------------- public — pairing exchange ---------------

    @app.post(
        "/api/v1/pair",
        response_model=PairResponse,
        tags=["pair"],
        responses={
            401: {"description": "Invalid, expired, used, or locked-out code"},
            429: {"description": "Rate limit exceeded"},
        },
    )
    @limiter.limit("10/minute")
    def pair(request: Request, body: PairRequest) -> PairResponse:
        """Exchange a short-lived pairing code for a per-device API token.

        The code is single-use, time-limited (5 min default), and locks out
        after 3 failed attempts. The plaintext token returned here is the
        only time it appears — the server stores only its SHA-256 hash.
        Rate-limited per source IP to defeat online brute force.
        """
        ip = _client_ip(request)
        try:
            issued, _record = pairing_store.redeem(
                body.code,
                ip=ip,
                device_label=body.device_label,
                platform=body.platform,
                token_store=token_store,
            )
        except PairingError as err:
            # Penalize the specific code (lock out after 3 strikes) so a
            # leaked code can't be brute-forced even within rate limits.
            try:
                pairing_store.record_failed_attempt(err.code, ip)
            except Exception as exc:  # noqa: BLE001
                log.debug("record_failed_attempt: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(err),
            ) from err

        return PairResponse(
            token=issued.plaintext,
            device_id=issued.record["id"],
            name=server_display_name,
            scopes=list(issued.record.get("scopes") or []),
        )

    # --------------- protected — status & reports ---------------

    @app.get("/api/v1/status", tags=["status"], dependencies=[Depends(require_read)])
    def get_status() -> JSONResponse:
        """Return the latest heartbeat — same shape as public /status.json."""
        state_cfg = config.get("notifications", "status_file", default={}) or {}
        path_str = state_cfg.get("path") or "/var/www/html/watchlog/status.json"
        path = Path(path_str)
        if not path.is_file():
            raise HTTPException(
                status_code=503,
                detail=(
                    f"No heartbeat at {path}. Either watchlog hasn't run yet or "
                    f"status_file reporter isn't enabled."
                ),
            )
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail=f"Heartbeat corrupt: {exc}") from exc
        # Compute age in seconds for convenience
        try:
            ran_at = datetime.fromisoformat(data["ran_at"])
            data["age_seconds"] = int(
                (datetime.now(timezone.utc) - ran_at).total_seconds()
            )
        except (KeyError, ValueError):
            data["age_seconds"] = None
        return JSONResponse(data)

    @app.get("/api/v1/reports", tags=["reports"], dependencies=[Depends(require_read)])
    def list_reports() -> dict[str, Any]:
        """Calendar view of past runs. Each day is summarized with the
        worst severity seen, the count of runs, and the latest run
        timestamp — enough for the mobile history browser to color the
        date list without a per-day round-trip."""
        log_dir = Path(config.get("state", "log_dir", default="/var/log/watchlog") or
                       "/var/log/watchlog")
        if not log_dir.is_dir():
            return {"days": []}

        sev_rank = {"OK": 0, "INFO": 1, "WARN": 2, "CRITICAL": 3}
        sev_name = {0: "OK", 1: "INFO", 2: "WARN", 3: "CRITICAL"}

        summaries: list[dict[str, Any]] = []
        for path in sorted(
            (p for p in log_dir.glob("*.json") if p.stem != "status"),
            key=lambda p: p.stem,
            reverse=True,
        )[:90]:
            try:
                runs = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(runs, list):
                continue
            worst_rank = 0
            last_ran_at: str | None = None
            for run in runs:
                last_ran_at = run.get("ran_at") or last_ran_at
                for r in run.get("results", []):
                    rank = sev_rank.get(r.get("severity"), 0)
                    if rank > worst_rank:
                        worst_rank = rank
            summaries.append({
                "date": path.stem,
                "worst_severity": sev_name[worst_rank],
                "runs": len(runs),
                "last_ran_at": last_ran_at,
            })
        # Backwards compat: keep the flat 'days' list (old clients).
        return {
            "days": [s["date"] for s in summaries],
            "summaries": summaries,
        }

    @app.get(
        "/api/v1/reports/{date}",
        tags=["reports"],
        dependencies=[Depends(require_read)],
    )
    def get_reports_for(date: str = FPath(..., pattern=r"^\d{4}-\d{2}-\d{2}$")) -> Any:
        log_dir = Path(config.get("state", "log_dir", default="/var/log/watchlog") or
                       "/var/log/watchlog")
        path = log_dir / f"{date}.json"
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"No archive for {date}")
        return json.loads(path.read_text())

    # --------------- protected — runs (trigger) ---------------

    @app.post(
        "/api/v1/runs",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_act)],
    )
    def trigger_run() -> ActionResult:
        return _run_command(["watchlog", "run"])

    # --------------- protected — state (snooze/ignore) ---------------

    @app.get("/api/v1/state", tags=["state"], dependencies=[Depends(require_read)])
    def get_state() -> dict[str, Any]:
        return State.load().to_dict()

    # --------------- protected — host metadata ---------------

    @app.get(
        "/api/v1/host",
        tags=["meta"],
        dependencies=[Depends(require_read)],
    )
    def get_host_info() -> dict[str, Any]:
        """Static-ish host info: hostname, OS release, kernel, RAM/disk
        totals, uptime, IPs. Mobile renders this as a server-detail
        header so the user can quickly see *which* box they're looking
        at without grepping through check titles."""
        return collect_host_info()

    # --------------- protected — check explainers ---------------

    @app.get(
        "/api/v1/checks/info",
        tags=["meta"],
        dependencies=[Depends(require_read)],
    )
    def checks_info() -> dict[str, Any]:
        """Return human-readable explanations for every check + the
        severity legend. Both are bilingual (en/pl); mobile picks based
        on locale and falls back to en. Static, generic across
        deployments — safe to cache aggressively client-side."""
        return {
            "checks": CHECK_INFO,
            "severity": SEVERITY_LEGEND,
            "version": __version__,
        }

    @app.post("/api/v1/state/snooze", tags=["state"], dependencies=[Depends(require_act)])
    def snooze(body: SnoozeRequest) -> dict[str, Any]:
        until = datetime.now(timezone.utc) + timedelta(hours=body.hours)
        State.load().snooze(body.check, until, by="api")
        return {"ok": True, "check": body.check, "until": until.isoformat()}

    @app.post("/api/v1/state/ignore", tags=["state"], dependencies=[Depends(require_act)])
    def ignore_check(body: IgnoreRequest) -> dict[str, Any]:
        State.load().ignore(body.check, by="api")
        return {"ok": True, "check": body.check}

    @app.delete(
        "/api/v1/state/snooze/{check}",
        tags=["state"],
        dependencies=[Depends(require_act)],
    )
    def unsnooze(check: str) -> dict[str, Any]:
        State.load().unsnooze(check)
        return {"ok": True, "check": check}

    @app.delete(
        "/api/v1/state/ignore/{check}",
        tags=["state"],
        dependencies=[Depends(require_act)],
    )
    def unignore(check: str) -> dict[str, Any]:
        State.load().unignore(check)
        return {"ok": True, "check": check}

    # --------------- protected — privileged actions ---------------

    @app.post(
        "/api/v1/actions/apply-security",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_act)],
    )
    def apply_security() -> ActionResult:
        audit("ACTION_APPLY_SECURITY")
        return _run_command(["unattended-upgrade", "-v"])

    # --------------- protected — audit log (Phase 3Q) ----------------------

    @app.get(
        "/api/v1/audit",
        tags=["meta"],
        dependencies=[Depends(require_read)],
    )
    def audit_list(
        limit: int = 200,
        kind: str | None = None,
    ) -> dict[str, Any]:
        """Return recent entries from /var/log/watchlog/audit.log.

        Mobile clients use this to surface 'what did I just do' lists
        (per-server action history). The log is newline-delimited
        JSON; this endpoint reads from the end of the file rather
        than parsing the whole thing.

        Query params:
          limit (int, 1..1000)   default 200, capped server-side
          kind  (str, optional)  match events whose 'event' field
                                 starts with this prefix. Examples:
                                 'ACTION_' for action shortcuts only,
                                 'TOKEN_'  for pairing/revoke trail.
        """
        from watchlog.auth import AUDIT_PATH  # noqa: PLC0415
        limit = max(1, min(int(limit), 1000))

        if not AUDIT_PATH.is_file():
            return {"entries": [], "total": 0}

        # Read the last N lines without loading the whole file.
        # 200 lines * ~250 bytes ≈ 50 KB → reading the last 256 KB
        # window is plenty even for verbose deployments.
        try:
            file_size = AUDIT_PATH.stat().st_size
            with AUDIT_PATH.open("rb") as fh:
                window = min(file_size, 256 * 1024)
                fh.seek(file_size - window)
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return {"entries": [], "total": 0}

        # Drop a potentially-partial first line when we didn't read
        # from byte 0 — it's the cut-off prefix of an earlier event.
        lines = tail.splitlines()
        if window < file_size and lines:
            lines = lines[1:]

        entries: list[dict[str, Any]] = []
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if kind and not str(rec.get("event", "")).startswith(kind):
                continue
            entries.append(rec)
            if len(entries) >= limit:
                break

        return {"entries": entries, "total": len(entries)}

    # --------------- protected — service / host actions (Phase 2D) ---------

    @app.get(
        "/api/v1/actions",
        tags=["actions"],
        dependencies=[Depends(require_read)],
    )
    def list_actions(request: Request) -> dict[str, Any]:
        """List the action shortcuts the operator has enabled in
        config.yaml. Mobile clients iterate this to render their
        actions panel — services not on the whitelist simply don't
        show up.

        Read-scope is enough; the actions themselves are gated by
        require_act when invoked.
        """
        actions_cfg = config.get("actions", default={}) or {}
        allowed = actions_cfg.get("allowed_services") or []
        allow_reboot = bool(actions_cfg.get("allow_reboot", False))
        allow_logs = bool(actions_cfg.get("allow_logs", True))

        descriptors: list[dict[str, Any]] = []
        for svc in allowed:
            if not isinstance(svc, str) or not svc:
                continue
            descriptors.append({
                "kind": "restart_service",
                "target": svc,
                "label": f"Restart {svc}",
                "destructive": False,
            })
            if allow_logs:
                descriptors.append({
                    "kind": "tail_logs",
                    "target": svc,
                    "label": f"Logs: {svc}",
                    "destructive": False,
                })
        if allow_reboot:
            descriptors.append({
                "kind": "reboot",
                "target": "host",
                "label": "Reboot server",
                "destructive": True,
            })
        return {"actions": descriptors}

    @app.post(
        "/api/v1/actions/restart-service",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_act)],
    )
    def restart_service(
        body: RestartServiceRequest,
        request: Request,
    ) -> ActionResult:
        """Restart a single systemd unit. Service must be in the
        operator's `actions.allowed_services` whitelist — anything
        else is rejected. Audit log records the attempt regardless of
        outcome."""
        actions_cfg = config.get("actions", default={}) or {}
        allowed = set(actions_cfg.get("allowed_services") or [])
        if body.service not in allowed:
            audit(
                "ACTION_RESTART_DENIED",
                service=body.service,
                ip=_client_ip(request),
                reason="not_whitelisted",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Service '{body.service}' is not on the allowed list. "
                       f"Add it to actions.allowed_services in config.yaml.",
            )
        audit(
            "ACTION_RESTART_SERVICE",
            service=body.service,
            ip=_client_ip(request),
        )
        return _run_command(["systemctl", "restart", body.service])

    @app.post(
        "/api/v1/actions/reboot",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_act)],
    )
    def reboot_host(request: Request) -> ActionResult:
        """Reboot the host. Disabled by default — operator must
        explicitly set `actions.allow_reboot: true` in config.yaml.
        We schedule the reboot one minute in the future so the API
        response can return cleanly before the kernel comes down."""
        actions_cfg = config.get("actions", default={}) or {}
        if not actions_cfg.get("allow_reboot", False):
            audit(
                "ACTION_REBOOT_DENIED",
                ip=_client_ip(request),
                reason="disabled_in_config",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Reboot via API is disabled. Set "
                       "actions.allow_reboot: true in config.yaml to allow it.",
            )
        audit("ACTION_REBOOT", ip=_client_ip(request))
        # +1 means "+1 minute" — gives admins a window to abort with
        # `shutdown -c` if the request was a mistake.
        return _run_command(["shutdown", "-r", "+1", "watchlog API reboot"])

    @app.post(
        "/api/v1/actions/logs",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_act)],
    )
    def tail_logs(
        body: TailLogsRequest,
        request: Request,
    ) -> ActionResult:
        """Stream the last N lines of journalctl output for a
        whitelisted service. Read-only — no log mutation possible."""
        actions_cfg = config.get("actions", default={}) or {}
        allowed = set(actions_cfg.get("allowed_services") or [])
        if not actions_cfg.get("allow_logs", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Log tailing via API is disabled.",
            )
        if body.service not in allowed and body.service != "system":
            audit(
                "ACTION_LOGS_DENIED",
                service=body.service,
                ip=_client_ip(request),
                reason="not_whitelisted",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Service '{body.service}' is not on the allowed list.",
            )
        audit(
            "ACTION_TAIL_LOGS",
            service=body.service,
            lines=body.lines,
            ip=_client_ip(request),
        )
        if body.service == "system":
            argv = ["journalctl", "-n", str(body.lines), "--no-pager"]
        else:
            argv = ["journalctl", "-u", body.service,
                    "-n", str(body.lines), "--no-pager"]
        return _run_command(argv)

    # --------------- protected — push notification registration ---------------

    @app.post(
        "/api/v1/push/register",
        tags=["push"],
        dependencies=[Depends(require_push)],
    )
    def push_register(
        body: PushRegisterRequest,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> dict[str, Any]:
        # Resolve the calling per-device token so we can link the FCM
        # token back to it. Quiet-hours / severity-floor filtering at
        # send time uses this link to find the right preferences.
        api_token_id: str | None = None
        if creds is not None:
            record = token_store.find_by_token(creds.credentials)
            if record is not None:
                api_token_id = record.get("id")
        registry = TokenRegistry()
        new = registry.register(
            body.token,
            body.platform,
            body.device_label,
            api_token_id=api_token_id,
        )
        return {
            "ok": True,
            "newly_registered": new,
            "total_devices": len(registry.all_tokens()),
        }

    @app.delete(
        "/api/v1/push/register/{token}",
        tags=["push"],
        dependencies=[Depends(require_push)],
    )
    def push_unregister(token: str) -> dict[str, Any]:
        registry = TokenRegistry()
        removed = registry.unregister(token)
        return {"ok": True, "removed": removed}

    @app.get(
        "/api/v1/push/preferences",
        tags=["push"],
    )
    def push_preferences_get(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> dict[str, Any]:
        """Read the calling device's notification preferences.

        We don't gate this through `require_push` because we need to
        identify the *specific* token making the call so we can return
        ITS prefs — not arbitrary devices. The admin token has no
        per-device prefs, so it gets defaults back.
        """
        if creds is None or creds.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        record = token_store.find_by_token(creds.credentials)
        if record is None:
            # Admin token (or no per-device tokens at all) — return defaults.
            from watchlog.auth import _default_notification_prefs
            return _default_notification_prefs()
        return token_store.get_preferences(record["id"])

    @app.patch(
        "/api/v1/push/preferences",
        tags=["push"],
    )
    def push_preferences_patch(
        body: NotificationPreferencesPayload,
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> dict[str, Any]:
        """Update the calling device's notification preferences. Same
        identification rationale as the GET: we change the specific
        token that authenticated this request, not arbitrary devices.

        Unset fields are ignored (PATCH semantics) — clients can update
        a single knob (e.g. flip quiet_hours_enabled) without resending
        the full blob.
        """
        if creds is None or creds.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        record = token_store.find_by_token(creds.credentials)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The admin token has no per-device preferences. "
                       "Pair a device first.",
            )
        # Only forward fields the client actually sent.
        partial = body.model_dump(exclude_none=True)
        # Normalize severity strings to upper case so the FCM filter
        # treats "warn" and "WARN" the same way.
        for key in ("quiet_min_severity", "min_severity"):
            if key in partial and isinstance(partial[key], str):
                partial[key] = partial[key].upper()
        merged = token_store.update_preferences(record["id"], partial)
        if merged is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Token disappeared",
            )
        return merged

    @app.get(
        "/api/v1/push/devices",
        tags=["push"],
        dependencies=[Depends(require_push)],
    )
    def push_list() -> dict[str, Any]:
        registry = TokenRegistry()
        # Don't leak full tokens — show first 16 chars only
        return {
            "devices": [
                {
                    "token_prefix": e["token"][:16] + "...",
                    "platform": e.get("platform"),
                    "device_label": e.get("device_label"),
                    "registered_at": e.get("registered_at"),
                }
                for e in registry.all_entries()
            ],
        }

    return app


def _server_display_name(config: Config) -> str:
    """Best-effort display name for this server, used as a hint for newly
    paired mobile clients. Prefers an explicit `api.name` config value,
    falling back to the system hostname."""
    api_cfg = config.get("api", default={}) or {}
    explicit = api_cfg.get("name") if isinstance(api_cfg, dict) else None
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    try:
        return socket.gethostname() or "watchlog"
    except OSError:
        return "watchlog"


def _client_ip(request: Request) -> str | None:
    """Extract the client IP, honoring X-Forwarded-For when the daemon is
    behind a reverse proxy (nginx). Falls back to the direct peer."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        # Use the leftmost address — that's the original client per RFC 7239
        return fwd.split(",", 1)[0].strip() or None
    if request.client:
        return request.client.host
    return None


def _run_command(argv: list[str]) -> ActionResult:
    log.info("API running command: %s", shlex.join(argv))
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=600, check=False
        )
    except subprocess.SubprocessError as exc:
        return ActionResult(
            ok=False, exit_code=-1, output=f"{type(exc).__name__}: {exc}",
            command=shlex.join(argv),
        )
    out = (proc.stdout or "") + (proc.stderr or "")
    return ActionResult(
        ok=proc.returncode == 0,
        exit_code=proc.returncode,
        output=out[-8000:],
        command=shlex.join(argv),
    )


# --------------- entry point ---------------


def serve(config: Config, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run the API server. Blocking call. Used by the CLI."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError("uvicorn missing — pip install 'watchlog[api]'") from exc

    app = create_app(config)
    log.info("watchlog API starting on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)
