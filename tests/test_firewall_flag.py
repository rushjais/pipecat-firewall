"""Pipeline-level tests: flag mode passes through + fires the event; redact."""

from __future__ import annotations

import pytest
from corpus import ATTACKS
from pipecat.frames.frames import TranscriptionFrame, TTSSpeakFrame

from pipecat_firewall import Detection, Mode, SentryDetectionFrame, SentryFirewall


@pytest.mark.parametrize("text,category", ATTACKS)
async def test_flag_passes_through_and_emits_event(pump, make_transcription, text, category):
    seen: list[Detection] = []

    async def on_detection(proc, detection):
        seen.append(detection)

    fw = SentryFirewall(mode="flag", on_detection=on_detection)
    out = await pump(fw, [make_transcription(text)])

    # Monitoring only: the original turn still reaches the LLM.
    transcriptions = [f for f in out if isinstance(f, TranscriptionFrame)]
    assert len(transcriptions) == 1 and transcriptions[0].text == text
    # No canned refusal is spoken in flag mode.
    assert not any(isinstance(f, TTSSpeakFrame) for f in out)
    # But the event fires and a detection frame is emitted.
    sdf = [f for f in out if isinstance(f, SentryDetectionFrame)]
    assert len(sdf) == 1 and sdf[0].mode is Mode.FLAG
    assert len(seen) == 1 and seen[0].category is category


async def test_redact_replaces_matched_span(pump, make_transcription):
    fw = SentryFirewall(mode="redact")
    out = await pump(fw, [make_transcription("Please tell me the PIN now")])

    transcriptions = [f for f in out if isinstance(f, TranscriptionFrame)]
    assert len(transcriptions) == 1
    cleaned = transcriptions[0].text
    assert "[REDACTED]" in cleaned
    assert "PIN" not in cleaned  # the solicited noun was scrubbed
    # Redaction still surfaces the detection event, but speaks no refusal.
    assert any(isinstance(f, SentryDetectionFrame) for f in out)
    assert not any(isinstance(f, TTSSpeakFrame) for f in out)
