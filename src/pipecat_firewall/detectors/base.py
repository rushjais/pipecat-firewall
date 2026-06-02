"""Detector ABC and the deterministic regex-signal base.

A :class:`Detector` answers one question: *does this text contain adversarial
content of my kind?* — returning a :class:`Detection` or ``None``. The
:class:`RegexSignalDetector` is the deterministic, zero-latency implementation
that drives the three default inbound detectors from the curated vocabulary in
:mod:`pipecat_firewall.signals`.

Detectors are pure and synchronous: matching curated regexes is microseconds, so
there's no reason to make ``detect`` async or stateful. The optional LLM
classifier (later) gets its own async path in the firewall, not here.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from ..signals import Signal
from ..types import Category, Detection, Severity

# Higher = more severe. Used to pick the strongest match when several signals in
# a detector fire on the same text, so the reported Detection is the worst case.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Detector(ABC):
    """Inspects a piece of text for one category of adversarial content."""

    #: Stable identifier used for selection (``detectors=[...]``) and the registry.
    name: str
    #: The category this detector reports.
    category: Category

    @abstractmethod
    def detect(self, text: str) -> Detection | None:
        """Return a :class:`Detection` if ``text`` is adversarial, else ``None``."""
        raise NotImplementedError


class RegexSignalDetector(Detector):
    """Deterministic detector backed by a list of :class:`Signal` regexes.

    Subclasses set :attr:`name`, :attr:`category`, and :attr:`signals`. All
    patterns are compiled once (case-insensitive) at construction. ``detect``
    scans every signal and returns the highest-severity match — deterministic
    matches always report ``confidence == 1.0``.
    """

    #: The vocabulary this detector matches; set by each subclass.
    signals: list[Signal] = []

    def __init__(self) -> None:
        # Compile once; pair each compiled pattern with its source Signal.
        self._compiled: list[tuple[re.Pattern[str], Signal]] = [
            (re.compile(sig.pattern, re.IGNORECASE), sig) for sig in self.signals
        ]

    def detect(self, text: str) -> Detection | None:
        if not text:
            return None
        best: tuple[re.Match[str], Signal] | None = None
        for pattern, sig in self._compiled:
            match = pattern.search(text)
            if match is None:
                continue
            if best is None or _SEVERITY_RANK[sig.severity] > _SEVERITY_RANK[best[1].severity]:
                best = (match, sig)
        if best is None:
            return None
        match, sig = best
        return Detection(
            category=self.category,
            severity=sig.severity,
            confidence=1.0,
            matched_text=match.group(0),
            signal=sig.name,
            raw_text=text,
        )
