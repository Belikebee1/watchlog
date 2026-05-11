"""FCM push reporter — sends a push notification to all registered devices.

Respects the same severity threshold (`only_when`) and snooze/ignore state
as the email and Telegram reporters.

Each device gets one notification per emit, with:
  - title: "<emoji> watchlog @ <hostname>"
  - body:  "<count> item(s) need attention: <first 2 titles>"
  - data:  {worst_severity, host, host_label, deeplink}

The mobile app uses the `data` payload to decide where to navigate when the
notification is tapped (deeplink schema: watchlog://status/<host>).
"""

from __future__ import annotations

import logging
import socket

from watchlog.auth import TokenStore, should_deliver
from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.core.severity import Severity
from watchlog.fcm import FcmSender, TokenRegistry
from watchlog.notifications import NotificationStateStore
from watchlog.reporters.base import Reporter
from watchlog.state import State

log = logging.getLogger(__name__)


@register_reporter("fcm_push")
class FcmPushReporter(Reporter):
    name = "fcm_push"

    def emit(self, results: list[CheckResult]) -> None:
        if not self.config.get("enabled", False):
            return

        sa_path = self.config.get("service_account_path")
        if not sa_path:
            log.warning("fcm_push enabled but service_account_path not set")
            return

        threshold = Severity.from_str(self.config.get("only_when", "warn"))
        worst = max((r.severity for r in results), default=Severity.OK)
        if worst < threshold:
            return

        # Filter out silenced checks
        state = State.load()
        actionable = [
            r for r in results
            if r.severity >= threshold and not state.is_silenced(r.check_name)
        ]
        if not actionable:
            return

        registry = TokenRegistry()
        tokens = registry.all_tokens()
        if not tokens:
            log.info("fcm_push: no registered tokens, skipping")
            return

        host = socket.gethostname()
        actual_worst = max(r.severity for r in actionable)

        # Per-device preferences: each FCM token may carry its own quiet
        # hours / severity floor. Skip tokens that say "no" for this
        # alert. Tokens predating the api_token_id linkage (registered
        # by an older mobile build) get the defaults — same behavior as
        # before this knob existed.
        token_store = TokenStore()
        notifications = NotificationStateStore()
        delivery_targets: list[str] = []
        # Track per-target what the reporter will record on successful
        # send. Mapping fcm_token → (api_token_id, [(check, severity)]).
        record_plans: dict[str, tuple[str, list[tuple[str, str]]]] = {}
        suppressed_prefs = 0
        suppressed_cooldown = 0
        actionable_check_names = [r.check_name for r in actionable]
        actionable_pairs = [(r.check_name, r.severity.name) for r in actionable]

        for fcm_token in tokens:
            api_id = registry.api_token_id_for(fcm_token)
            prefs = token_store.get_preferences(api_id) if api_id else None

            # Preferences filter (severity floor, quiet hours, disabled
            # checks). Skips before consulting cooldown — saves a JSON
            # read on muted devices.
            if prefs is not None and not should_deliver(
                prefs,
                actual_worst.name,
                actionable_checks=actionable_check_names,
            ):
                suppressed_prefs += 1
                continue

            # Smart grouping (Phase 2H): suppress repeats within the
            # device's cooldown window unless something escalated.
            if api_id is None:
                # Devices that predate api_token_id linkage skip the
                # cooldown — old behaviour, no surprises.
                delivery_targets.append(fcm_token)
                continue
            cooldown = int((prefs or {}).get("cooldown_hours", 12))
            decision = notifications.decide(
                api_id, actionable_pairs, cooldown_hours=cooldown,
            )
            if not decision.deliver:
                suppressed_cooldown += 1
                continue
            delivery_targets.append(fcm_token)
            record_plans[fcm_token] = (api_id, actionable_pairs)

        if not delivery_targets:
            log.info(
                "fcm_push: every device suppressed (prefs=%d, cooldown=%d), "
                "skipping",
                suppressed_prefs, suppressed_cooldown,
            )
            return

        title = f"{actual_worst.emoji()} watchlog @ {host}"
        first_titles = " · ".join(r.title for r in actionable[:2])
        if len(actionable) > 2:
            first_titles += f" · +{len(actionable) - 2} more"
        body = first_titles[:300]

        sender = FcmSender(sa_path)
        successes, invalid = sender.send_to_tokens(
            delivery_targets,
            title=title,
            body=body,
            data={
                "worst_severity": actual_worst.name,
                "host": host,
                "actionable_count": str(len(actionable)),
                "deeplink": "watchlog://status",
            },
        )
        log.info(
            "fcm_push: sent to %d/%d devices, %d invalid, %d prefs, "
            "%d cooldown",
            successes, len(delivery_targets), len(invalid),
            suppressed_prefs, suppressed_cooldown,
        )
        if invalid:
            registry.remove_invalid(invalid)
            # Record push state for devices that actually got the send.
            # Note: we don't have per-token success info from FcmSender
            # — for now treat 'not invalid' as 'delivered'. Idempotent
            # record (same state written again) is harmless.
            invalid_set = set(invalid)
            for fcm_token, (api_id, pairs) in record_plans.items():
                if fcm_token not in invalid_set:
                    notifications.record_push(api_id, pairs)
        else:
            for api_id, pairs in record_plans.values():
                notifications.record_push(api_id, pairs)
