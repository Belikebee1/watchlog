"""Core primitives: config loading, severity levels, check base class, runner."""

from watchlog.core.check import Check, CheckResult
from watchlog.core.config import Config, load_config
from watchlog.core.runner import Runner
from watchlog.core.severity import Severity

__all__ = ["Check", "CheckResult", "Config", "Runner", "Severity", "load_config"]
