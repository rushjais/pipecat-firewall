# Changelog

All notable changes to `pipecat-firewall` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/) and the project adheres
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Package scaffold (src layout, `pyproject.toml` with hatchling backend).
- Core types: `Detection` dataclass, `Category`, `Mode`, and `Severity` enums.
- `signals.py` — deterministic phrase/regex vocabulary for prompt injection,
  PII-extraction, and policy-override, plus outbound PII patterns (SSN/PIN/CVV).
  Seeded and generalized from the SENTRY adversarial corpus.
- `refusals.py` — default canned refusal lines and refusal exemplars.
- Detector ABC (`detectors/base.py`) + `RegexSignalDetector`, the three
  deterministic inbound detectors (`prompt_injection`, `pii_extraction`,
  `policy_override`), and a name-based detector registry.
- `SentryFirewall` inbound FrameProcessor: inspects final `TranscriptionFrame`s
  after STT and enforces `block` (swallow + speak a canned `TTSSpeakFrame`
  refusal, bypassing the LLM), `flag` (pass through + fire event), and `redact`
  (scrub the matched span). Supports `allowlist`, `min_confidence`,
  `refusal_message`, an `on_detection` event handler, and emits
  `SentryDetectionFrame` downstream.
- Frame-pump test harness (`conftest.py`) plus unit tests per detector and
  pipeline-level block/flag/redact tests against the extracted attack/benign
  corpus. **124 tests, all green.**

_The outbound `SentryLeakGuard` and the optional LLM classifier land in later
steps._
