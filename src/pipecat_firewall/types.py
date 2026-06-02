"""Core value types for pipecat-firewall.

These are dependency-free dataclasses/enums shared by the detectors, the
FrameProcessors, and the downstream ``SentryDetectionFrame``. Nothing here
imports Pipecat, so they're cheap to use in tests and in user callbacks.

The ``Category`` values are kept identical to the SENTRY dashboard taxonomy
strings (``pii_extraction``, ``policy_override`` …) so firewall events stay
continuous with the existing SENTRY board. Note the one rename: SENTRY tagged
role-override / system-prompt-leak attacks as ``jailbreak``; here that maps to
the clearer ``PROMPT_INJECTION``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Category(str, Enum):
    """What kind of adversarial content a detector matched.

    Inheriting from ``str`` means the member compares/serializes as its value
    (e.g. ``Category.PII_EXTRACTION == "pii_extraction"``), which keeps the
    dashboard/JSON payloads clean.
    """

    PROMPT_INJECTION = "prompt_injection"  # SENTRY taxonomy: "jailbreak"
    PII_EXTRACTION = "pii_extraction"
    POLICY_OVERRIDE = "policy_override"
    PII_LEAK = "pii_leak"  # outbound only (SentryLeakGuard)


class Mode(str, Enum):
    """How the firewall enforces a detection."""

    BLOCK = "block"  # swallow the frame + speak a canned refusal
    FLAG = "flag"  # pass through, but fire the event (monitoring only)
    REDACT = "redact"  # replace matched text with [REDACTED] (mainly outbound)


class Severity(str, Enum):
    """Rough impact ranking, used for prioritization/dashboards only.

    Severity never gates enforcement — that's the firewall's ``mode`` and
    ``min_confidence``. It's metadata for whoever consumes the detection.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Detection:
    """The result of a detector firing on a piece of text.

    Attributes:
        category: Which adversarial category matched.
        severity: Rough impact ranking (metadata only).
        confidence: 0.0–1.0. Deterministic signals report ``1.0``; the optional
            LLM classifier reports a fuzzy score gated by ``min_confidence``.
        matched_text: The exact substring that tripped the detector.
        signal: Identifier of the specific signal/rule that matched (for
            debugging, metrics, and allowlist tuning).
        raw_text: The full text that was inspected.
    """

    category: Category
    severity: Severity
    confidence: float
    matched_text: str
    signal: str
    raw_text: str
