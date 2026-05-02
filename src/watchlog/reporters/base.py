"""Base reporter class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from watchlog.core.check import CheckResult


class Reporter(ABC):
    """Reporters consume a list of CheckResult and emit them somewhere."""

    name: str = ""

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def emit(self, results: list[CheckResult]) -> None: ...
