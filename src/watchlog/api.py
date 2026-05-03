"""REST API daemon — FastAPI app exposing watchlog state and actions over HTTP.

Endpoints (all require Bearer auth except /health and /):
    GET  /                          Dashboard SPA (HTML)
    GET  /api/v1                    API metadata
    GET  /api/v1/health             Public liveness
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

The token is read from /etc/watchlog/config.yaml -> api.token (or generated if missing).
"""

from __future__ import annotations

import json
import logging
import secrets
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from fastapi import Depends, FastAPI, HTTPException, Path as FPath, status
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "watchlog[api] extras not installed. Run: pip install 'watchlog[api]'"
    ) from exc

from watchlog import __version__
from watchlog.core.config import Config
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


class ActionResult(BaseModel):
    ok: bool
    exit_code: int
    output: str = Field(..., description="Combined stdout+stderr (last 8 KB)")
    command: str


# --------------- App factory ---------------


def create_app(config: Config) -> FastAPI:
    """Build a FastAPI app bound to the given config.

    The token comes from config.notifications.api.token. If absent, the API will
    run open — DON'T DO THIS IF THE PORT IS PUBLIC. The CLI generates a token on
    install if none exists.
    """
    api_cfg = config.get("api", default={}) or {}
    expected_token: str = (api_cfg.get("token") if isinstance(api_cfg, dict) else "") or ""

    app = FastAPI(
        title="watchlog API",
        version=__version__,
        description=(
            "REST API for the watchlog server health monitor. "
            "All endpoints except `/api/v1/health` and `/` require Bearer authentication."
        ),
        docs_url="/docs",
        redoc_url=None,
    )

    # --------------- auth dependency ---------------

    def require_token(
        creds: HTTPAuthorizationCredentials | None = Depends(SECURITY),
    ) -> None:
        if not expected_token:
            # Open mode — caller is responsible for not exposing this publicly.
            return
        if creds is None or creds.scheme.lower() != "bearer" or not secrets.compare_digest(
            creds.credentials, expected_token
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

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

    # --------------- protected — status & reports ---------------

    @app.get("/api/v1/status", tags=["status"], dependencies=[Depends(require_token)])
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

    @app.get("/api/v1/reports", tags=["reports"], dependencies=[Depends(require_token)])
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
        dependencies=[Depends(require_token)],
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
        dependencies=[Depends(require_token)],
    )
    def trigger_run() -> ActionResult:
        return _run_command(["watchlog", "run"])

    # --------------- protected — state (snooze/ignore) ---------------

    @app.get("/api/v1/state", tags=["state"], dependencies=[Depends(require_token)])
    def get_state() -> dict[str, Any]:
        return State.load().to_dict()

    @app.post("/api/v1/state/snooze", tags=["state"], dependencies=[Depends(require_token)])
    def snooze(body: SnoozeRequest) -> dict[str, Any]:
        until = datetime.now(timezone.utc) + timedelta(hours=body.hours)
        State.load().snooze(body.check, until, by="api")
        return {"ok": True, "check": body.check, "until": until.isoformat()}

    @app.post("/api/v1/state/ignore", tags=["state"], dependencies=[Depends(require_token)])
    def ignore_check(body: IgnoreRequest) -> dict[str, Any]:
        State.load().ignore(body.check, by="api")
        return {"ok": True, "check": body.check}

    @app.delete(
        "/api/v1/state/snooze/{check}",
        tags=["state"],
        dependencies=[Depends(require_token)],
    )
    def unsnooze(check: str) -> dict[str, Any]:
        State.load().unsnooze(check)
        return {"ok": True, "check": check}

    @app.delete(
        "/api/v1/state/ignore/{check}",
        tags=["state"],
        dependencies=[Depends(require_token)],
    )
    def unignore(check: str) -> dict[str, Any]:
        State.load().unignore(check)
        return {"ok": True, "check": check}

    # --------------- protected — privileged actions ---------------

    @app.post(
        "/api/v1/actions/apply-security",
        response_model=ActionResult,
        tags=["actions"],
        dependencies=[Depends(require_token)],
    )
    def apply_security() -> ActionResult:
        return _run_command(["unattended-upgrade", "-v"])

    return app


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
