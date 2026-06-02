"""Policy-override detector (authority pretext + manufactured urgency)."""

from __future__ import annotations

from ..signals import POLICY_OVERRIDE
from ..types import Category
from .base import RegexSignalDetector


class PolicyOverrideDetector(RegexSignalDetector):
    """Catches "skip verification", "my manager authorized", "emergency wire"."""

    name = "policy_override"
    category = Category.POLICY_OVERRIDE
    signals = POLICY_OVERRIDE
