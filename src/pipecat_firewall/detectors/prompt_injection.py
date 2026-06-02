"""Prompt-injection / role-override detector."""

from __future__ import annotations

from ..signals import PROMPT_INJECTION
from ..types import Category
from .base import RegexSignalDetector


class PromptInjectionDetector(RegexSignalDetector):
    """Catches attempts to override the system prompt, role, or restrictions."""

    name = "prompt_injection"
    category = Category.PROMPT_INJECTION
    signals = PROMPT_INJECTION
