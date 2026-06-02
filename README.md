# pipecat-firewall

[![PyPI](https://img.shields.io/pypi/v/pipecat-firewall.svg)](https://pypi.org/project/pipecat-firewall/)
[![Python](https://img.shields.io/pypi/pyversions/pipecat-firewall.svg)](https://pypi.org/project/pipecat-firewall/)
[![CI](https://github.com/rushjais/pipecat-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/rushjais/pipecat-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A drop-in security firewall for [Pipecat](https://github.com/pipecat-ai/pipecat) voice agents.**
It reads each caller turn and **blocks, flags, or redacts** adversarial input —
prompt injection, attempts to extract PII (card numbers, SSN, PIN), and
policy-override pressure — *before* your LLM ever sees it.

```bash
pip install pipecat-firewall
```

→ **[pypi.org/project/pipecat-firewall](https://pypi.org/project/pipecat-firewall/)**

## Why you'd use it

- **Stops attacks before the LLM runs.** A blocked turn never reaches your model,
  so it can't be talked into leaking data or breaking policy — and you don't pay
  for the call.
- **Deterministic, zero added latency.** Clean turns pass straight through; the
  default detectors are curated regex/phrase matching (microseconds), with **no
  API key and no extra model call**.
- **Un-jailbreakable refusals.** On a block it speaks a canned reply that bypasses
  the LLM entirely, so there's no prompt to argue with.
- **One line to adopt.** Drop `SentryFirewall()` into your existing pipeline —
  nothing else changes. Detections also fire an event + a downstream frame you
  can wire into logging or a dashboard.

> **Status: 0.1.0 core.** The inbound `SentryFirewall` FrameProcessor ships with
> three deterministic detectors and block/flag/redact enforcement. The outbound
> `SentryLeakGuard` and the optional LLM classifier land in later releases.
>
> Tested against the `pipecat-ai` 0.0.x line (0.0.98–0.0.108); the dependency is
> capped `<1.0` because pipecat-ai 1.x restructures the frame API.

## The one-liner

```python
from pipecat_firewall import SentryFirewall

pipeline = Pipeline([
    transport.input(),
    stt,
    SentryFirewall(),          # ← detects & blocks adversarial input
    context_aggregator.user(),
    llm,
    tts,
    transport.output(),
    context_aggregator.assistant(),
])
```

## Detection categories

| Category | What it catches |
|---|---|
| `PROMPT_INJECTION` | "ignore previous instructions", developer mode, "repeat your system prompt" |
| `PII_EXTRACTION` | soliciting the agent to read back a card number, SSN, PIN, CVV |
| `POLICY_OVERRIDE` | "skip verification", "my manager authorized", manufactured urgency |
| `PII_LEAK` | outbound: Luhn-valid card numbers, SSN/PIN/CVV in the agent's response |

## License

MIT
