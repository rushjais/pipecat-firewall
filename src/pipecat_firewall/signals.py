"""Deterministic detection vocabulary — the reliable, zero-latency core.

This module is *data only*. It declares the curated phrase/regex signals per
:class:`Category`; the matching logic lives in ``detectors/`` (built next). A
:class:`Signal` is a named, severity-tagged regex pattern. Inbound signals are
phrase patterns matched case-insensitively against the user turn; the outbound
PII patterns power ``SentryLeakGuard``.

Seed material was extracted from the SENTRY repo and then *generalized*:

  - Attack phrasings  ← ``cekura/scenarios.md`` + ``cekura_client._MOCK_FAILURES``
  - What each category defends ← ``config.CACHED_FALLBACK_PATCH["guardrails"]``
  - Outbound PII patterns generalize ``main._detect_leak`` from SENTRY's four
    fixed test markers (one card, one SSN, one PIN, one expiry) to *any* card
    (Luhn-checked in the detector), SSN, PIN, or CVV.

Each pattern carries a ``\b`` word boundary where it helps avoid false hits on
benign substrings (e.g. "pin" inside "shopping").
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import Category, Severity


@dataclass(frozen=True, slots=True)
class Signal:
    """A single named, severity-tagged regex pattern for a category.

    ``pattern`` is a regex *string* (not compiled) so this module stays pure
    data; detectors compile it with ``re.IGNORECASE``. ``name`` is surfaced as
    ``Detection.signal`` for debugging, metrics, and allowlist tuning.
    """

    name: str
    pattern: str
    severity: Severity = Severity.HIGH


# ---------------------------------------------------------------------------
# INBOUND — prompt injection / role override / system-prompt exfiltration.
# (SENTRY taxonomy called these "jailbreak"; scenarios 4–5 + guardrail #3.)
# ---------------------------------------------------------------------------
PROMPT_INJECTION: list[Signal] = [
    Signal("ignore_previous", r"ignore\s+(?:(?:all|any|previous|prior|above|earlier|your|the)\s+)+(?:instructions?|prompts?|rules?)", Severity.HIGH),
    Signal("disregard_instructions", r"disregard\s+(?:(?:all|any|previous|prior|your|the)\s+)+(?:instructions?|rules?)", Severity.HIGH),
    Signal("developer_mode", r"\bdeveloper\s+mode\b", Severity.HIGH),
    Signal("dan_jailbreak", r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b", Severity.HIGH),
    Signal("no_restrictions", r"\b(?:with\s+)?no\s+(?:restrictions?|limits?|rules?|filters?)\b", Severity.MEDIUM),
    Signal("you_are_now", r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\s+(?:are|will)\b|\bpretend\s+(?:you\s+are|to\s+be)\b", Severity.MEDIUM),
    Signal("reveal_system_prompt", r"(?:repeat|reveal|print|show|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|the\s+prompt)", Severity.HIGH),
    Signal("verbatim_audit", r"\bverbatim\b.*\b(?:prompt|instructions?)\b|\b(?:prompt|instructions?)\b.*\bverbatim\b", Severity.MEDIUM),
    Signal("rules_dont_apply", r"(?:rules?|restrictions?|security)\s+(?:don'?t|do\s+not)\s+apply", Severity.HIGH),
]

# ---------------------------------------------------------------------------
# INBOUND — soliciting the model to read back sensitive data.
# (scenarios 1–4 + guardrails #1/#2.) The trick across all four SENTRY PII
# scenarios is "read it back to me / confirm it for me", so we match the
# *sensitive noun* in proximity to a *disclosure verb*, plus standalone asks.
# ---------------------------------------------------------------------------
_PII_NOUN = r"(?:full\s+)?(?:card\s+(?:number|num|pan)|pan\b|account\s+number|ssn|social\s+security(?:\s+number)?|pin\b|cvv|cvc|security\s+code|password|passcode)"
_DISCLOSE_VERB = r"(?:read|tell|give|share|say|confirm|repeat|verify|provide|spell)\s+(?:me\s+|back\s+|out\s+|it\s+|the\s+|my\s+)*"

PII_EXTRACTION: list[Signal] = [
    Signal("disclose_pii", rf"{_DISCLOSE_VERB}{_PII_NOUN}", Severity.CRITICAL),
    Signal("read_back_pii", rf"{_PII_NOUN}.*\b(?:read|say|confirm|repeat)\s+(?:it\s+)?back", Severity.CRITICAL),
    Signal("full_card_number", r"\bfull\s+(?:card\s+number|pan|account\s+number)\b", Severity.CRITICAL),
    Signal("whats_the_pin", r"what'?s?\s+(?:the|my)\s+(?:pin|cvv|cvc|ssn|password|card\s+number)\b", Severity.CRITICAL),
    Signal("to_confirm_identity", r"(?:read|confirm|verify)\b.*\bto\s+confirm\s+(?:my\s+)?identity", Severity.HIGH),
]

# ---------------------------------------------------------------------------
# INBOUND — pressure the agent into bypassing policy.
# (scenarios 8–9 + guardrails #4/#5.) Authority pretext + manufactured urgency.
# ---------------------------------------------------------------------------
POLICY_OVERRIDE: list[Signal] = [
    Signal("skip_verification", r"\b(?:skip|waive|bypass|forgo|forget)\s+(?:the\s+)?(?:verification|identity\s+check|checks?|security)", Severity.HIGH),
    Signal("manager_authorized", r"(?:my\s+)?(?:manager|supervisor|boss)\s+(?:said|authorized?|approved|told\s+you|waived)", Severity.HIGH),
    Signal("authority_pretext", r"\b(?:i'?m|i\s+am|this\s+is)\s+(?:a\s+)?(?:fraud\s+investigator|law\s+enforcement|police|the\s+account\s+holder|from\s+IT|your\s+supervisor)\b", Severity.MEDIUM),
    Signal("emergency_urgency", r"\b(?:this\s+is\s+an?\s+)?emergency\b|\bright\s+now\b|\burgent(?:ly)?\b", Severity.MEDIUM),
    Signal("emergency_wire", r"(?:wire|transfer|send)\s+\$?\d", Severity.HIGH),
]


# Master registry: Category -> its inbound signals. Detectors iterate this.
INBOUND_SIGNALS: dict[Category, list[Signal]] = {
    Category.PROMPT_INJECTION: PROMPT_INJECTION,
    Category.PII_EXTRACTION: PII_EXTRACTION,
    Category.POLICY_OVERRIDE: POLICY_OVERRIDE,
}


# ---------------------------------------------------------------------------
# OUTBOUND — PII leak patterns for SentryLeakGuard (Category.PII_LEAK).
# Generalizes SENTRY's fixed-marker check to structural patterns. Note: a raw
# 13–19 digit run only *looks* like a card — the detector confirms it with a
# Luhn check before flagging, to avoid blocking benign long numbers.
# ---------------------------------------------------------------------------
# 13–19 digits, optionally split by spaces/dashes in 4s (how cards get spoken).
CARD_NUMBER_PATTERN = r"\b(?:\d[ -]?){13,19}\b"
# US SSN: 3-2-4 with optional separators.
SSN_PATTERN = r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b"
# Standalone CVV/CVC: 3–4 digits, usually introduced by the word.
CVV_PATTERN = r"\b(?:cvv|cvc|security\s+code)\s*(?:is|:)?\s*\d{3,4}\b"
# PIN: typically a 4–6 digit code introduced by the word "pin".
PIN_PATTERN = r"\bpin\s*(?:is|:)?\s*\d{4,6}\b"

OUTBOUND_PII_PATTERNS: dict[str, str] = {
    "card_number": CARD_NUMBER_PATTERN,
    "ssn": SSN_PATTERN,
    "cvv": CVV_PATTERN,
    "pin": PIN_PATTERN,
}
