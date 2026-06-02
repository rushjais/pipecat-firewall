"""Unit tests for PiiExtractionDetector."""

from __future__ import annotations

import pytest
from corpus import ATTACKS_BY_CATEGORY, BENIGN

from pipecat_firewall import Category
from pipecat_firewall.detectors import PiiExtractionDetector

ATTACKS = ATTACKS_BY_CATEGORY[Category.PII_EXTRACTION]


@pytest.fixture
def detector() -> PiiExtractionDetector:
    return PiiExtractionDetector()


@pytest.mark.parametrize("text", ATTACKS)
def test_detects_pii_extraction(detector: PiiExtractionDetector, text: str) -> None:
    detection = detector.detect(text)
    assert detection is not None, f"missed: {text!r}"
    assert detection.category is Category.PII_EXTRACTION
    assert detection.confidence == 1.0


@pytest.mark.parametrize("text", BENIGN)
def test_ignores_benign(detector: PiiExtractionDetector, text: str) -> None:
    assert detector.detect(text) is None, f"false positive: {text!r}"
