"""Tests for the detector registry and selection helper."""

from __future__ import annotations

import pytest
from corpus import ATTACKS, BENIGN

from pipecat_firewall.detectors import (
    DEFAULT_DETECTORS,
    DETECTOR_REGISTRY,
    build_detectors,
)


def test_default_set_is_the_three_inbound_detectors() -> None:
    assert DEFAULT_DETECTORS == ("prompt_injection", "pii_extraction", "policy_override")
    assert set(DETECTOR_REGISTRY) == set(DEFAULT_DETECTORS)


def test_build_default_and_custom_order() -> None:
    assert [d.name for d in build_detectors()] == list(DEFAULT_DETECTORS)
    names = ["pii_extraction", "prompt_injection"]
    assert [d.name for d in build_detectors(names)] == names


def test_unknown_detector_raises() -> None:
    with pytest.raises(ValueError, match="unknown detector"):
        build_detectors(["nope"])


def _first_detection(text: str):
    for detector in build_detectors():
        result = detector.detect(text)
        if result is not None:
            return result
    return None


@pytest.mark.parametrize("text,category", ATTACKS)
def test_full_stack_detects_every_attack(text: str, category) -> None:
    detection = _first_detection(text)
    assert detection is not None, f"missed: {text!r}"
    assert detection.category is category


@pytest.mark.parametrize("text", BENIGN)
def test_full_stack_clean_on_benign(text: str) -> None:
    assert _first_detection(text) is None, f"false positive: {text!r}"
