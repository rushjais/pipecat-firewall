"""Detectors: the ABC, the deterministic inbound detectors, and a registry.

The registry maps each detector's ``name`` to its class so the firewall can
resolve ``detectors=["prompt_injection", ...]`` to instances. The outbound
PII-leak detector and optional LLM classifier register here in later steps.
"""

from __future__ import annotations

from .base import Detector, RegexSignalDetector
from .pii_extraction import PiiExtractionDetector
from .policy_override import PolicyOverrideDetector
from .prompt_injection import PromptInjectionDetector

#: name -> Detector class. The three deterministic inbound detectors, in the
#: order they run by default.
DETECTOR_REGISTRY: dict[str, type[Detector]] = {
    PromptInjectionDetector.name: PromptInjectionDetector,
    PiiExtractionDetector.name: PiiExtractionDetector,
    PolicyOverrideDetector.name: PolicyOverrideDetector,
}

#: The default detector set when the caller doesn't specify one.
DEFAULT_DETECTORS: tuple[str, ...] = tuple(DETECTOR_REGISTRY)


def build_detectors(names: list[str] | tuple[str, ...] | None = None) -> list[Detector]:
    """Instantiate detectors by name, preserving the given order.

    Args:
        names: Detector names to build. ``None`` builds the full default set.

    Raises:
        ValueError: if a requested name isn't registered.
    """
    selected = DEFAULT_DETECTORS if names is None else tuple(names)
    out: list[Detector] = []
    for name in selected:
        try:
            cls = DETECTOR_REGISTRY[name]
        except KeyError:
            known = ", ".join(sorted(DETECTOR_REGISTRY))
            raise ValueError(f"unknown detector {name!r}; available: {known}") from None
        out.append(cls())
    return out


__all__ = [
    "Detector",
    "RegexSignalDetector",
    "PromptInjectionDetector",
    "PiiExtractionDetector",
    "PolicyOverrideDetector",
    "DETECTOR_REGISTRY",
    "DEFAULT_DETECTORS",
    "build_detectors",
]
