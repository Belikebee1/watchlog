"""Authentication, pairing, and per-device token management.

Three durable stores live under /var/lib/watchlog/:

  tokens.json    — registry of per-device API tokens. Tokens are stored as
                   SHA-256 hashes; plaintext is shown ONCE at issuance and
                   never written.

  pairings.json  — short-lived pairing codes used to securely hand a freshly
                   minted token to a mobile device. Each code has a TTL
                   (default 5 min) and is single-use; after redemption the
                   plaintext token is returned to the redeemer and the
                   pairing is marked used. Codes lock out after 3 failed
                   redemption attempts to defeat online brute force.

  audit.log      — newline-delimited JSON of every security-relevant event
                   (token issued, token revoked, pair generated, pair
                   redeemed, pair failed). Useful for forensics if a token
                   is suspected compromised.

The legacy /etc/watchlog/config.yaml `api.token` continues to work and is
treated as the "admin" / master token with all scopes. It cannot be revoked
through the API — only by editing the config and restarting the daemon.
"""

from __future__ import annotations

import base64
import dataclasses
import fcntl
import hashlib
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DATA_DIR = Path("/var/lib/watchlog")
LOG_DIR = Path("/var/log/watchlog")

TOKENS_PATH = DATA_DIR / "tokens.json"
PAIRINGS_PATH = DATA_DIR / "pairings.json"
AUDIT_PATH = LOG_DIR / "audit.log"

# Tokens issued by pairing default to all three scopes. Future read-only
# tokens can be issued with --scopes read via `watchlog api qr`.
ALL_SCOPES = ("read", "act", "push")
DEFAULT_SCOPES = list(ALL_SCOPES)

# Pairing code: 6 base32 characters from RFC 4648 alphabet (A-Z, 2-7) — 32^6
# ≈ 1.07 billion combinations. Combined with rate limiting and 3-strike
# lockout, online brute force is infeasible.
PAIRING_CODE_LEN = 6
PAIRING_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
PAIRING_DEFAULT_TTL_SECONDS = 300
PAIRING_MAX_TTL_SECONDS = 600
PAIRING_MAX_FAILED_ATTEMPTS = 3
PAIRING_RETENTION_SECONDS = 24 * 3600

TOKEN_PREFIX = "wlk_"


# --------------- helpers ---------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_notification_prefs() -> dict[str, Any]:
    """Default per-device notification preferences. Each new pairing
    starts with these; the mobile app PATCHes overrides as the user
    tweaks them.

    Schema:
        quiet_hours_enabled: bool
            When false, quiet_* fields are ignored. Default off — pairing
            shouldn't surprise the user with silent push.
        quiet_start, quiet_end: 'HH:MM' 24h strings
            The window during which notifications below
            quiet_min_severity get suppressed. quiet_end <= quiet_start
            is allowed and means "spans midnight" (the common case).
        quiet_timezone: IANA name (e.g. 'Europe/Warsaw')
            What clock the user's quiet window references. Falls back to
            the server's timezone if missing — but the mobile app sends
            the device's TZ at first save, so this is effectively
            always set on real-world deployments.
        quiet_min_severity: 'OK' / 'INFO' / 'WARN' / 'CRITICAL'
            Severities at or above this threshold ALWAYS deliver, even
            during quiet hours. Default 'CRITICAL' — quiet hours never
            silence true emergencies.
        min_severity: 'OK' / 'INFO' / 'WARN' / 'CRITICAL'
            Global floor. Severities below this never push, regardless
            of quiet hours. Default 'WARN' — same behavior as before
            this knob existed.
    """
    return {
        "quiet_hours_enabled": False,
        "quiet_start": "22:00",
        "quiet_end": "07:00",
        "quiet_timezone": None,
        "quiet_min_severity": "CRITICAL",
        "min_severity": "WARN",
        # Phase 2F: per-check muting. Names of checks the user does
        # not want push notifications about — e.g. ["apt_updates",
        # "fail2ban_stats"]. Server-side semantics: if EVERY actionable
        # check in a given run is on this list, the push is suppressed
        # for the device. If at least one non-disabled check fired,
        # the standard "N items need attention" push goes through (it
        # may still mention disabled checks in the title — we don't
        # rewrite per-device messages yet, that's a future refinement).
        "disabled_checks": [],
    }


def should_deliver(
    prefs: dict[str, Any],
    severity: str,
    *,
    actionable_checks: list[str] | None = None,
    now: datetime | None = None,
) -> bool:
    """Evaluate a device's notification preferences for an alert at the
    given severity. Returns True if the push should be delivered.

    Logic:
      1. If actionable_checks is provided AND every name in it is on
         the device's disabled_checks list, drop. This handles the
         per-check muting introduced in Phase 2F: a run consisting
         only of muted checks raises no push for this device, but
         a mixed run still delivers.
      2. If severity < min_severity, drop. (per-device floor)
      3. If quiet_hours_enabled AND we're inside the quiet window AND
         severity < quiet_min_severity, drop.
      4. Otherwise deliver.

    The `now` arg is provided for testability — callers normally leave
    it None and we use the current UTC instant.
    """
    disabled = set(prefs.get("disabled_checks") or [])
    if actionable_checks and disabled:
        if all(name in disabled for name in actionable_checks):
            return False

    sev = severity_rank(severity)
    floor = severity_rank(prefs.get("min_severity", "WARN"))
    if sev < floor:
        return False

    if not prefs.get("quiet_hours_enabled"):
        return True

    quiet_floor = severity_rank(prefs.get("quiet_min_severity", "CRITICAL"))
    if sev >= quiet_floor:
        return True  # critical override

    if not _in_quiet_window(prefs, now=now):
        return True
    return False


def _in_quiet_window(
    prefs: dict[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """True when the device's current local time falls inside its
    configured quiet window. The window is interpreted in the device's
    [quiet_timezone] (falling back to UTC if unset), so the check is
    correct regardless of where the watchlog server itself runs."""
    start_str = (prefs.get("quiet_start") or "").strip()
    end_str = (prefs.get("quiet_end") or "").strip()
    if not start_str or not end_str:
        return False
    try:
        start_h, start_m = [int(x) for x in start_str.split(":", 1)]
        end_h, end_m = [int(x) for x in end_str.split(":", 1)]
    except ValueError:
        return False

    tz_name = prefs.get("quiet_timezone")
    tz = None
    if tz_name:
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(tz_name)
        except Exception:  # noqa: BLE001
            tz = None

    instant = now or _utcnow()
    if tz is not None:
        instant = instant.astimezone(tz)
    minutes = instant.hour * 60 + instant.minute
    start_min = start_h * 60 + start_m
    end_min = end_h * 60 + end_m
    if start_min == end_min:
        return False
    if start_min < end_min:
        return start_min <= minutes < end_min
    # Spans midnight (e.g. 22:00 - 07:00).
    return minutes >= start_min or minutes < end_min


def severity_rank(name: str) -> int:
    """Map a severity name to the same integer ordering as the Python
    [Severity] enum. Used by the FCM filter when comparing the alert's
    severity against the device's threshold without importing the runner
    module (avoids circular imports)."""
    return {
        "OK": 0,
        "INFO": 1,
        "WARN": 2,
        "CRITICAL": 3,
    }.get((name or "").upper(), 1)


def _hash_token(token: str) -> str:
    """SHA-256 of the plaintext token, hex-encoded."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token_id() -> str:
    return "tok_" + base64.b32encode(os.urandom(8)).decode().rstrip("=").lower()


def _new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def _new_pairing_code() -> str:
    return "".join(secrets.choice(PAIRING_ALPHABET) for _ in range(PAIRING_CODE_LEN))


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON to a tmp file then rename — never leaves a half-written file
    behind even on crash. Uses fcntl LOCK_EX on the destination dir handle to
    serialize concurrent writers from the same Python process."""
    _ensure_dirs()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Failed to load %s: %s — starting fresh", path, exc)
        return default


# --------------- audit log ---------------


_audit_lock = threading.Lock()


def audit(event: str, **fields: Any) -> None:
    """Append a structured event to the audit log. Never raises — auditing
    must not be allowed to break the request path. Fields are merged into the
    JSON line; ts and event are guaranteed to be present."""
    _ensure_dirs()
    record: dict[str, Any] = {"ts": _iso(_utcnow()), "event": event}
    record.update({k: v for k, v in fields.items() if v is not None})
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        with _audit_lock:
            with AUDIT_PATH.open("a", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                fh.write(line)
        try:
            os.chmod(AUDIT_PATH, 0o640)
        except OSError:
            pass
    except OSError as exc:
        log.error("Failed to append audit event %s: %s", event, exc)


# --------------- token store ---------------


@dataclasses.dataclass(frozen=True)
class IssuedToken:
    """The plaintext token returned to the caller at issuance time. The
    plaintext is NEVER persisted; only `record` (which contains the hash) is
    stored in tokens.json."""

    plaintext: str
    record: dict[str, Any]


class TokenStore:
    """Persistent registry of per-device API tokens.

    All public methods are safe to call concurrently from threads — they
    serialize on a process-wide lock. We deliberately don't try to be safe
    against simultaneous *processes* writing the file, because in practice
    only the API daemon (one process) and the CLI write here, and the CLI
    only runs interactively under sudo. The atomic-rename in
    _atomic_write_json keeps readers consistent.
    """

    _lock = threading.Lock()

    def __init__(self, path: Path = TOKENS_PATH) -> None:
        self.path = path

    def _load(self) -> dict[str, Any]:
        return _load_json(self.path, {"tokens": []})

    def _save(self, data: dict[str, Any]) -> None:
        _atomic_write_json(self.path, data)

    def issue(
        self,
        *,
        device_label: str | None,
        platform: str | None,
        scopes: list[str] | None = None,
        issued_via: str = "pairing",
    ) -> IssuedToken:
        """Mint a fresh token, persist its hash + metadata, return plaintext."""
        plaintext = _new_token()
        token_hash = _hash_token(plaintext)
        record = {
            "id": _new_token_id(),
            "token_hash": token_hash,
            "device_label": device_label,
            "platform": platform,
            "scopes": list(scopes) if scopes else list(DEFAULT_SCOPES),
            "issued_via": issued_via,
            "created_at": _iso(_utcnow()),
            "last_used_at": None,
            "last_used_ip": None,
            "revoked": False,
            "revoked_at": None,
            "revoked_reason": None,
            # Default notification preferences: no quiet hours, deliver
            # everything at WARN+. Users tune these from the mobile app.
            "notification_preferences": _default_notification_prefs(),
        }
        with self._lock:
            data = self._load()
            data["tokens"].append(record)
            self._save(data)
        audit(
            "TOKEN_ISSUED",
            token_id=record["id"],
            platform=platform,
            device_label=device_label,
            issued_via=issued_via,
            scopes=record["scopes"],
        )
        return IssuedToken(plaintext=plaintext, record=record)

    def update_preferences(
        self, token_id: str, prefs: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Replace the notification_preferences blob for a token. The
        new prefs are merged on top of defaults so partial updates from
        the client (e.g. just tweaking quiet_end) don't accidentally
        clear other fields. Returns the resulting prefs dict, or None
        if the token wasn't found / was revoked."""
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                if rec.get("id") == token_id and not rec.get("revoked"):
                    base = rec.get("notification_preferences") or {}
                    merged = {**_default_notification_prefs(), **base, **prefs}
                    rec["notification_preferences"] = merged
                    self._save(data)
                    audit(
                        "TOKEN_PREFS_UPDATED",
                        token_id=token_id,
                        prefs=merged,
                    )
                    return merged
        return None

    def get_preferences(self, token_id: str) -> dict[str, Any]:
        """Read the current preferences for a token, or defaults if the
        token has none stored (older issuance)."""
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                if rec.get("id") == token_id and not rec.get("revoked"):
                    base = rec.get("notification_preferences") or {}
                    return {**_default_notification_prefs(), **base}
        return _default_notification_prefs()

    def find_by_token(self, plaintext: str) -> dict[str, Any] | None:
        """Return the active record for the given plaintext token, or None
        if no match or the matching token has been revoked. Constant-time
        comparison against every stored hash."""
        if not plaintext:
            return None
        candidate_hash = _hash_token(plaintext)
        match: dict[str, Any] | None = None
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                stored = rec.get("token_hash", "")
                if not stored:
                    continue
                # secrets.compare_digest is constant-time on equal-length
                # inputs; padding to equal length is unnecessary because
                # SHA-256 hex outputs are always 64 chars.
                if secrets.compare_digest(stored, candidate_hash):
                    match = rec
                    break
        if match is None or match.get("revoked"):
            return None
        return match

    def touch(self, token_id: str, ip: str | None) -> None:
        """Update last_used_at / last_used_ip on a token. Best-effort —
        failures don't break the request path. Skipped silently if the
        record was revoked or removed since lookup."""
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                if rec.get("id") == token_id and not rec.get("revoked"):
                    rec["last_used_at"] = _iso(_utcnow())
                    rec["last_used_ip"] = ip
                    self._save(data)
                    return

    def revoke(self, token_id: str, reason: str = "user") -> bool:
        """Mark a token revoked. Returns True if a token was revoked, False
        if the id doesn't exist or was already revoked."""
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                if rec.get("id") == token_id and not rec.get("revoked"):
                    rec["revoked"] = True
                    rec["revoked_at"] = _iso(_utcnow())
                    rec["revoked_reason"] = reason
                    self._save(data)
                    audit(
                        "TOKEN_REVOKED",
                        token_id=token_id,
                        reason=reason,
                    )
                    return True
        return False

    def revoke_all(self, reason: str = "revoke_all") -> int:
        """Revoke every active token. Returns the count revoked."""
        count = 0
        with self._lock:
            data = self._load()
            for rec in data["tokens"]:
                if not rec.get("revoked"):
                    rec["revoked"] = True
                    rec["revoked_at"] = _iso(_utcnow())
                    rec["revoked_reason"] = reason
                    audit(
                        "TOKEN_REVOKED",
                        token_id=rec.get("id"),
                        reason=reason,
                    )
                    count += 1
            self._save(data)
        return count

    def list_active(self) -> list[dict[str, Any]]:
        """Return non-sensitive views of every non-revoked token."""
        data = self._load()
        out: list[dict[str, Any]] = []
        for rec in data["tokens"]:
            if rec.get("revoked"):
                continue
            out.append({
                "id": rec.get("id"),
                "device_label": rec.get("device_label"),
                "platform": rec.get("platform"),
                "scopes": rec.get("scopes", []),
                "created_at": rec.get("created_at"),
                "last_used_at": rec.get("last_used_at"),
                "last_used_ip": rec.get("last_used_ip"),
                "issued_via": rec.get("issued_via"),
            })
        return out


# --------------- pairing store ---------------


class PairingError(Exception):
    """Raised when a pairing code cannot be redeemed. Always carries a
    machine-friendly `code` for the audit log; the message is what we'd be
    willing to show to the redeemer (kept generic to avoid information
    leakage)."""

    def __init__(self, code: str, message: str = "Invalid or expired code"):
        super().__init__(message)
        self.code = code


class PairingStore:
    _lock = threading.Lock()

    def __init__(self, path: Path = PAIRINGS_PATH) -> None:
        self.path = path

    def _load(self) -> dict[str, Any]:
        return _load_json(self.path, {"pairings": []})

    def _save(self, data: dict[str, Any]) -> None:
        _atomic_write_json(self.path, data)

    def _gc(self, data: dict[str, Any]) -> None:
        """Drop pairings older than retention. Called inside the lock."""
        cutoff = _utcnow() - timedelta(seconds=PAIRING_RETENTION_SECONDS)
        kept: list[dict[str, Any]] = []
        for p in data["pairings"]:
            try:
                created = datetime.fromisoformat(
                    p["created_at"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError):
                continue
            if created >= cutoff:
                kept.append(p)
        data["pairings"] = kept

    def generate(
        self,
        *,
        ttl_seconds: int = PAIRING_DEFAULT_TTL_SECONDS,
        scopes: list[str] | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Create a new pairing record. Returns the full record (callers
        only need .code and .expires_at, but the rest is included for
        transparency and testing)."""
        ttl = max(1, min(int(ttl_seconds), PAIRING_MAX_TTL_SECONDS))
        now = _utcnow()
        record = {
            "code": _new_pairing_code(),
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=ttl)),
            "ttl_seconds": ttl,
            "scopes": list(scopes) if scopes else list(DEFAULT_SCOPES),
            "name": name,
            "used": False,
            "redeemed_at": None,
            "redeemed_token_id": None,
            "redeemed_ip": None,
            "failed_attempts": 0,
            "locked_out": False,
        }
        with self._lock:
            data = self._load()
            self._gc(data)
            # Defend against the (astronomically unlikely) collision with a
            # still-active code — generate until unique.
            existing = {p["code"] for p in data["pairings"] if not p.get("used")}
            while record["code"] in existing:
                record["code"] = _new_pairing_code()
            data["pairings"].append(record)
            self._save(data)
        audit(
            "PAIR_GENERATED",
            code=record["code"],
            ttl=ttl,
            scopes=record["scopes"],
        )
        return record

    def redeem(
        self,
        code: str,
        *,
        ip: str | None,
        device_label: str | None,
        platform: str | None,
        token_store: TokenStore,
    ) -> tuple[IssuedToken, dict[str, Any]]:
        """Atomically validate, mark used, and mint a token for a code.

        Returns (issued_token, pairing_record). Raises PairingError on any
        failure with a generic message — callers should NOT echo the error
        back verbatim, both to avoid information leakage and because the
        message is logged separately to audit.
        """
        normalized = (code or "").strip().upper()
        if not normalized:
            audit("PAIR_FAILED", reason="empty_code", ip=ip)
            raise PairingError(normalized, "Invalid or expired code")

        with self._lock:
            data = self._load()
            self._gc(data)
            target: dict[str, Any] | None = None
            for p in data["pairings"]:
                if p.get("code") == normalized:
                    target = p
                    break
            if target is None:
                audit("PAIR_FAILED", reason="not_found", code=normalized, ip=ip)
                raise PairingError(normalized)
            if target.get("used"):
                audit("PAIR_FAILED", reason="already_used", code=normalized, ip=ip)
                raise PairingError(normalized)
            if target.get("locked_out"):
                audit("PAIR_FAILED", reason="locked_out", code=normalized, ip=ip)
                raise PairingError(normalized)
            try:
                expires = datetime.fromisoformat(
                    target["expires_at"].replace("Z", "+00:00")
                )
            except (KeyError, ValueError):
                audit("PAIR_FAILED", reason="malformed", code=normalized, ip=ip)
                raise PairingError(normalized)
            if _utcnow() >= expires:
                audit("PAIR_FAILED", reason="expired", code=normalized, ip=ip)
                raise PairingError(normalized)

            # All preconditions pass. Mint token + mark redeemed atomically.
            issued = token_store.issue(
                device_label=device_label,
                platform=platform,
                scopes=target.get("scopes") or list(DEFAULT_SCOPES),
                issued_via="pairing",
            )
            target["used"] = True
            target["redeemed_at"] = _iso(_utcnow())
            target["redeemed_token_id"] = issued.record["id"]
            target["redeemed_ip"] = ip
            self._save(data)

        audit(
            "PAIR_REDEEMED",
            code=normalized,
            token_id=issued.record["id"],
            ip=ip,
            device_label=device_label,
            platform=platform,
        )
        return issued, target

    def record_failed_attempt(self, code: str, ip: str | None) -> None:
        """Increment failed_attempts on a code (if it exists). Locks out
        the code once the threshold is reached. Called by the API layer
        when redeem() raises and the caller wants to penalize the IP/code
        binding rather than just the IP."""
        normalized = (code or "").strip().upper()
        if not normalized:
            return
        with self._lock:
            data = self._load()
            for p in data["pairings"]:
                if p.get("code") == normalized and not p.get("used"):
                    p["failed_attempts"] = int(p.get("failed_attempts", 0)) + 1
                    if p["failed_attempts"] >= PAIRING_MAX_FAILED_ATTEMPTS:
                        p["locked_out"] = True
                        audit(
                            "PAIR_LOCKED_OUT",
                            code=normalized,
                            attempts=p["failed_attempts"],
                            ip=ip,
                        )
                    self._save(data)
                    return
