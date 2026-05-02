"""Config loader — reads YAML from a path and validates basic structure."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATHS = [
    Path("/etc/watchlog/config.yaml"),
    Path("./config.yaml"),
]


@dataclass
class Config:
    """Parsed configuration."""

    raw: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None

    def get(self, *keys: str, default: Any = None) -> Any:
        """Drill into nested dict by keys, return default if missing."""
        node: Any = self.raw
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key)
            if node is None:
                return default
        return node

    def check_config(self, name: str) -> dict[str, Any]:
        """Per-check config dict."""
        return self.get("checks", name, default={}) or {}

    def check_enabled(self, name: str) -> bool:
        return bool(self.check_config(name).get("enabled", False))

    def reporter_config(self, name: str) -> dict[str, Any]:
        return self.get("notifications", name, default={}) or {}

    def reporter_enabled(self, name: str) -> bool:
        return bool(self.reporter_config(name).get("enabled", False))


def load_config(path: Path | None = None) -> Config:
    """Load config from given path or first found in DEFAULT_PATHS.

    Raises FileNotFoundError if no config found and no path given.
    """
    if path is None:
        for candidate in DEFAULT_PATHS:
            if candidate.is_file():
                path = candidate
                break
        else:
            raise FileNotFoundError(
                f"No watchlog config found. Looked in: {', '.join(str(p) for p in DEFAULT_PATHS)}. "
                "Use --config to specify a path, or create /etc/watchlog/config.yaml."
            )
    else:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r") as f:
        raw = yaml.safe_load(f) or {}

    return Config(raw=raw, path=path)
