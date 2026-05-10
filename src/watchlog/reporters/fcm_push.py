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
        delivery_targets: list[str] = []
        suppressed = 0
        actionable_check_names = [r.check_name for r in actionable]
        for fcm_token in tokens:
            api_id = registry.api_token_id_for(fcm_token)
            prefs = token_store.get_preferences(api_id) if api_id else None
            ok = prefs is None or should_deliver(
                prefs,
                actual_worst.name,
                actionable_checks=actionable_check_names,
            )
            if ok:
                delivery_targets.append(fcm_token)
            else:
                suppressed += 1

        if not delivery_targets:
            log.info(
                "fcm_push: every device suppressed by preferences, skipping",
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
            "fcm_push: sent to %d/%d devices, %d invalid, %d suppressed",
            successes, len(delivery_targets), len(invalid), suppressed,
        )
        if invalid:
            registry.remove_invalid(invalid)
