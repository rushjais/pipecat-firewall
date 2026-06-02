"""Frame-pump test harness.

``pump`` runs a processor inside a minimal real Pipecat pipeline
(``processor -> capture sink``) driven by a ``PipelineTask``, so
StartFrame/started state, queueing, and EndFrame are all handled exactly as in
production. It feeds the given frames and returns every frame the processor
pushed downstream (with the framework's own Start/End frames filtered out), so
tests can assert on what the firewall emitted.

The capture sink is built from *core* Pipecat primitives only
(``FrameProcessor`` + ``Pipeline``/``PipelineTask``/``PipelineRunner``). It
deliberately avoids ``pipecat.tests.utils``, which transitively imports optional
transport/service deps (``websockets``) that aren't part of pipecat-ai core.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import pytest
from pipecat.frames.frames import EndFrame, Frame, StartFrame, TranscriptionFrame
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.runner import PipelineRunner
from pipecat.pipeline.task import PipelineParams, PipelineTask
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor


class _CaptureSink(FrameProcessor):
    """Terminal processor that records every downstream frame it receives."""

    def __init__(self) -> None:
        super().__init__()
        self.captured: list[Frame] = []

    async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
        await super().process_frame(frame, direction)
        if direction == FrameDirection.DOWNSTREAM:
            self.captured.append(frame)
        await self.push_frame(frame, direction)


async def _pump(processor: FrameProcessor, frames: Sequence[Frame]) -> list[Frame]:
    """Send ``frames`` through ``processor``; return downstream frames it pushed."""
    sink = _CaptureSink()
    pipeline = Pipeline([processor, sink])
    task = PipelineTask(pipeline, params=PipelineParams(), cancel_on_idle_timeout=False)

    async def feed() -> None:
        await asyncio.sleep(0.01)  # let the runner start
        for frame in frames:
            await task.queue_frame(frame)
        await task.queue_frame(EndFrame())

    runner = PipelineRunner()
    await asyncio.gather(runner.run(task), feed())

    return [f for f in sink.captured if not isinstance(f, (StartFrame, EndFrame))]


@pytest.fixture
def pump():
    """Return the async frame-pump helper: ``await pump(processor, frames)``."""
    return _pump


@pytest.fixture
def make_transcription():
    """Return a factory for final ``TranscriptionFrame``s."""

    def _make(text: str, user_id: str = "caller") -> TranscriptionFrame:
        return TranscriptionFrame(text, user_id, "2026-01-01T00:00:00.000Z")

    return _make
