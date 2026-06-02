# pipecat-firewall

A real-time adversarial-input firewall for [Pipecat](https://github.com/pipecat-ai/pipecat)
voice agents. It inspects each user turn in real time and **blocks, flags, or
redacts** adversarial content — PII-extraction solicitation, prompt injection,
and policy-override — *before* the LLM acts on it.

Detection + enforcement only: deterministic, dependency-light, and
production-safe. Tested against the `pipecat-ai` 0.0.x line (0.0.98–0.0.108);
the dependency is capped `<1.0` because pipecat-ai 1.x restructures the frame
API (1.x support is future work).

> **Status: 0.1.0 core.** The inbound `SentryFirewall` FrameProcessor ships with
> three deterministic detectors and block/flag/redact enforcement. The outbound
> `SentryLeakGuard` and the optional LLM classifier land in later steps.

## Install

```bash
pip install pipecat-firewall
```

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
