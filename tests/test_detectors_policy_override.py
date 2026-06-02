"""Unit tests for PolicyOverrideDetector."""

from __future__ import annotations

import pytest
from corpus import ATTACKS_BY_CATEGORY, BENIGN

from pipecat_firewall import Category
from pipecat_firewall.detectors import PolicyOverrideDetector

ATTACKS = ATTACKS_BY_CATEGORY[Category.POLICY_OVERRIDE]


@pytest.fixture
def detector() -> PolicyOverrideDetector:
    return PolicyOverrideDetector()


@pytest.mark.parametrize("text", ATTACKS)
def test_detects_policy_override(detector: PolicyOverrideDetector, text: str) -> None:
    detection = detector.detect(text)
    assert detection is not None, f"missed: {text!r}"
    assert detection.category is Category.POLICY_OVERRIDE
    assert detection.confidence == 1.0


@pytest.mark.parametrize("text", BENIGN)
def test_ignores_benign(detector: PolicyOverrideDetector, text: str) -> None:
    assert detector.detect(text) is None, f"false positive: {text!r}"
