"""pipecat-firewall — a real-time adversarial-input firewall for Pipecat.

Detects and blocks PII-extraction solicitation, prompt injection, and
policy-override on each user turn *before* the LLM acts on it. Detection +
enforcement only — deterministic and production-safe.

The inbound ``SentryFirewall`` FrameProcessor and ``SentryDetectionFrame`` are
the shippable 0.1.0 core. The outbound ``SentryLeakGuard`` and the optional LLM
classifier land in later steps.
"""

from __future__ import annotations

from .firewall import SentryFirewall
from .frames import SentryDetectionFrame
from .types import Category, Detection, Mode, Severity

__version__ = "0.1.0"

__all__ = [
    "SentryFirewall",
    "SentryDetectionFrame",
    "Category",
    "Detection",
    "Mode",
    "Severity",
    # Coming in later steps:
    #   "SentryLeakGuard"
]
