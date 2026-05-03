"""Firebase Cloud Messaging (FCM) integration — token registry and push send.

This module manages the list of mobile devices that should receive push
notifications, and the actual sending via FCM HTTP v1 API. We use the
`firebase-admin` SDK because it handles JWT signing + OAuth2 token exchange
for FCM HTTP v1, which is non-trivial to do by hand.

Token registry: a single JSON file at /var/lib/watchlog/fcm-tokens.json.
Each entry: {token: "...", platform: "android|ios", registered_at: "..."}.

Tokens that FCM rejects with 404/410 ("not registered") are auto-removed.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_REGISTRY_PATH = Path("/var/lib/watchlog/fcm-tokens.json")
_LOCK = threading.Lock()


class TokenRegistry:
    """Persistent FCM token store with thread-safe atomic writes."""

    def __init__(self, path: Path | None = None):
        self._path = path or DEFAULT_REGISTRY_PATH
        self._tokens: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text())
            self._tokens = {t["token"]: t for t in data.get("tokens", [])}
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log.warning("Could not load FCM registry: %s", exc)

    def _save(self) -> None:
        with _LOCK:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {"tokens": list(self._tokens.values())},
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            tmp.replace(self._path)
            try:
                self._path.chmod(0o640)
            except OSError:
                pass

    def register(self, token: str, platform: str = "unknown",
                 device_label: str | None = None) -> bool:
        """Add or refresh a device token. Returns True if newly added."""
        new = token not in self._tokens
        self._tokens[token] = {
            "token": token,
            "platform": platform,
            "device_label": device_label,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        return new

    def unregister(self, token: str) -> bool:
        if token in self._tokens:
            del self._tokens[token]
            self._save()
            return True
        return False

    def all_tokens(self) -> list[str]:
        return list(self._tokens.keys())

    def all_entries(self) -> list[dict[str, Any]]:
        return list(self._tokens.values())

    def remove_invalid(self, invalid_tokens: list[str]) -> int:
        if not invalid_tokens:
            return 0
        removed = 0
        for t in invalid_tokens:
            if t in self._tokens:
                del self._tokens[t]
                removed += 1
        if removed:
            self._save()
        return removed


# --------------- FCM sender ---------------


class FcmSender:
    """Wraps firebase-admin to send notifications. Loaded lazily so that
    backends without `firebase-admin` installed (or no Service Account) still
    work — the FCM reporter just no-ops in that case."""

    def __init__(self, service_account_path: str):
        self._sa_path = Path(service_account_path)
        self._app = None
        self._init_error: Exception | None = None

    def _ensure_init(self) -> bool:
        if self._app is not None:
            return True
        if self._init_error is not None:
            return False
        try:
            import firebase_admin  # noqa: PLC0415
            from firebase_admin import credentials  # noqa: PLC0415
        except ImportError as exc:
            self._init_error = exc
            log.error(
                "firebase-admin not installed. Run: pip install 'watchlog[fcm]'"
            )
            return False

        if not self._sa_path.is_file():
            self._init_error = FileNotFoundError(
                f"Firebase Service Account JSON not found: {self._sa_path}"
            )
            log.error("%s", self._init_error)
            return False

        try:
            cred = credentials.Certificate(str(self._sa_path))
            # Use a named app to avoid clashing with other firebase_admin uses
            self._app = firebase_admin.initialize_app(cred, name="watchlog")
            return True
        except Exception as exc:  # noqa: BLE001
            self._init_error = exc
            log.exception("firebase_admin init failed: %s", exc)
            return False

    def send_to_tokens(
        self,
        tokens: list[str],
        title: str,
        body: str,
        data: dict[str, str] | None = None,
    ) -> tuple[int, list[str]]:
        """Send a notification to many device tokens.

        Returns (successes, invalid_tokens). The caller is expected to
        remove invalid_tokens from the registry.
        """
        if not tokens:
            return 0, []
        if not self._ensure_init():
            return 0, []

        from firebase_admin import messaging  # noqa: PLC0415

        successes = 0
        invalid: list[str] = []

        for token in tokens:
            msg = messaging.Message(
                token=token,
                notification=messaging.Notification(title=title, body=body),
                data=data or {},
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        channel_id="watchlog_alerts",
                        sound="default",
                    ),
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            sound="default",
                            badge=1,
                        ),
                    ),
                ),
            )
            try:
                messaging.send(msg, app=self._app)
                successes += 1
            except messaging.UnregisteredError:
                # Token was uninstalled / refreshed. Drop it.
                invalid.append(token)
            except messaging.SenderIdMismatchError:
                invalid.append(token)
            except Exception as exc:  # noqa: BLE001
                log.warning("FCM send failed for token %s...: %s",
                            token[:16], exc)

        return successes, invalid
