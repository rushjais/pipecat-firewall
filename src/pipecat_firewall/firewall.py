"""SentryFirewall — the inbound adversarial-input FrameProcessor.

Sits **after ``stt``, before ``context_aggregator.user()``**. It inspects each
final :class:`TranscriptionFrame`, runs the detectors, and enforces:

  - **block** (default): swallow the transcription so the LLM never sees the
    attack, then push a :class:`TTSSpeakFrame` canned refusal that bypasses the
    LLM entirely (a fully deterministic response).
  - **flag**: pass the transcription through unchanged, but still fire the event
    and emit a :class:`SentryDetectionFrame` (monitoring only).
  - **redact**: replace the matched span with ``[REDACTED]`` and pass the
    cleaned transcription through.

Clean turns are pushed through untouched — deterministic matching is
microseconds, so there's effectively zero added latency. Interim
transcriptions and all system/control frames pass straight through.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pipecat.frames.frames import (
    Frame,
    InterimTranscriptionFrame,
    TranscriptionFrame,
    TTSSpeakFrame,
)
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor

from .detectors import build_detectors
from .frames import SentryDetectionFrame
from .refusals import DEFAULT_REFUSAL, refusal_for
from .types import Detection, Mode

OnDetection = Callable[["SentryFirewall", Detection], Awaitable[None]]


class SentryFirewall(FrameProcessor):
    """Detects and blocks adversarial user input before the LLM acts on it.

    Args:
        mode: ``"block"`` | ``"flag"`` | ``"redact"`` (or a :class:`Mode`).
        detectors: detector names to run. ``None`` runs the default set
            (prompt_injection, pii_extraction, policy_override).
        refusal_message: spoken line when blocking. ``None`` uses a per-category
            default. Ignored in flag mode.
        allowlist: phrases that are never flagged (case-insensitive substring
            match against the turn).
        min_confidence: detections below this confidence pass through.
            Deterministic signals report ``1.0``; raise this to gate a future
            LLM classifier.
        llm_classifier: reserved for the optional fuzzy layer (not used in v1).
        on_detection: optional async callback ``(processor, detection)``, also
            subscribable via ``@firewall.event_handler("on_detection")``.
    """

    def __init__(
        self,
        *,
        mode: Mode | str = Mode.BLOCK,
        detectors: list[str] | None = None,
        refusal_message: str | None = None,
        allowlist: list[str] | None = None,
        min_confidence: float = 0.0,
        llm_classifier: object | None = None,
        on_detection: OnDetection | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._mode = Mode(mode)
        self._detectors = build_detectors(detectors)
        self._refusal_message = refusal_message
        self._allowlist = [a.lower() for a in (allowlist or [])]
        self._min_confidence = min_confidence
        self._llm_classifier = llm_classifier  # reserved for the [llm] extra

        self._register_event_handler("on_detection")
        if on_detection is not None:
            self.add_event_handler("on_detection", on_detection)

    async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
        # Let the base handle StartFrame/Interruption/Cancel bookkeeping first.
        await super().process_frame(frame, direction)

        # Act only on FINAL transcriptions. Interim results are partial and must
        # flow through untouched (InterimTranscriptionFrame is a sibling of
        # TranscriptionFrame, not a subclass, so this is just defensive clarity).
        if isinstance(frame, InterimTranscriptionFrame):
            await self.push_frame(frame, direction)
            return
        if isinstance(frame, TranscriptionFrame):
            await self._inspect(frame, direction)
            return

        # Everything else (system/control frames, audio, etc.) passes through.
        await self.push_frame(frame, direction)

    async def _inspect(self, frame: TranscriptionFrame, direction: FrameDirection) -> None:
        text = frame.text or ""

        if self._is_allowlisted(text):
            await self.push_frame(frame, direction)
            return

        detection = self._run_detectors(text)
        if detection is None or detection.confidence < self._min_confidence:
            await self.push_frame(frame, direction)
            return

        # A detection fired — notify observers regardless of mode.
        await self._call_event_handler("on_detection", detection)
        await self.push_frame(SentryDetectionFrame(detection=detection, mode=self._mode), direction)

        if self._mode is Mode.FLAG:
            # Monitoring only: let the original turn reach the LLM.
            await self.push_frame(frame, direction)
            return

        if self._mode is Mode.REDACT:
            cleaned = text.replace(detection.matched_text, "[REDACTED]")
            await self.push_frame(
                TranscriptionFrame(cleaned, frame.user_id, frame.timestamp), direction
            )
            return

        # BLOCK: swallow the transcription (the LLM never runs on the attack) and
        # speak a deterministic canned refusal that bypasses the LLM.
        await self.push_frame(TTSSpeakFrame(self._refusal_text(detection)), direction)

    def _run_detectors(self, text: str) -> Detection | None:
        """Return the first detection across the configured detectors, in order."""
        for detector in self._detectors:
            detection = detector.detect(text)
            if detection is not None:
                return detection
        return None

    def _is_allowlisted(self, text: str) -> bool:
        lowered = text.lower()
        return any(phrase in lowered for phrase in self._allowlist)

    def _refusal_text(self, detection: Detection) -> str:
        if self._refusal_message is not None:
            return self._refusal_message
        return refusal_for(detection.category) or DEFAULT_REFUSAL
