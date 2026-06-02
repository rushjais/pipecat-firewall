"""Unit tests for PromptInjectionDetector."""

from __future__ import annotations

import pytest
from corpus import ATTACKS_BY_CATEGORY, BENIGN

from pipecat_firewall import Category
from pipecat_firewall.detectors import PromptInjectionDetector

ATTACKS = ATTACKS_BY_CATEGORY[Category.PROMPT_INJECTION]


@pytest.fixture
def detector() -> PromptInjectionDetector:
    return PromptInjectionDetector()


@pytest.mark.parametrize("text", ATTACKS)
def test_detects_prompt_injection(detector: PromptInjectionDetector, text: str) -> None:
    detection = detector.detect(text)
    assert detection is not None, f"missed: {text!r}"
    assert detection.category is Category.PROMPT_INJECTION
    assert detection.confidence == 1.0
    assert detection.matched_text  # the span that fired
    assert detection.signal  # the named rule


@pytest.mark.parametrize("text", BENIGN)
def test_ignores_benign(detector: PromptInjectionDetector, text: str) -> None:
    assert detector.detect(text) is None, f"false positive: {text!r}"


def test_empty_text_is_none(detector: PromptInjectionDetector) -> None:
    assert detector.detect("") is None
