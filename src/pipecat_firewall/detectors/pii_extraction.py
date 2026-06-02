"""PII-extraction solicitation detector (inbound)."""

from __future__ import annotations

from ..signals import PII_EXTRACTION
from ..types import Category
from .base import RegexSignalDetector


class PiiExtractionDetector(RegexSignalDetector):
    """Catches asks to read back / disclose a card number, SSN, PIN, or CVV."""

    name = "pii_extraction"
    category = Category.PII_EXTRACTION
    signals = PII_EXTRACTION
