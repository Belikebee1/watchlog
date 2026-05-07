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
        log_dir = Path(config.get("state", "log_dir", default="/var/log/watchlog") or
                       "/var/log/watchlog")
        if not log_dir.is_dir():
            return {"days": []}
        days = sorted(
            (p.stem for p in log_dir.glob("*.json") if p.stem != "status"),
            reverse=True,
        )
        return {"days": days[:90]}

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
        return _run_command(["unattended-upgrade", "-v"])

    # --------------- protected — push notification registration ---------------

    @app.post(
        "/api/v1/push/register",
        tags=["push"],
        dependencies=[Depends(require_push)],
    )
    def push_register(body: PushRegisterRequest) -> dict[str, Any]:
        registry = TokenRegistry()
        new = registry.register(body.token, body.platform, body.device_label)
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
