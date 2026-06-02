"""Frame-pump test harness.

``pump`` runs a processor inside a minimal real Pipecat pipeline
(``processor -> sink``) driven by a ``PipelineTask``, so StartFrame/started
state, queueing, and EndFrame are all handled exactly as in production. It feeds
the given frames and returns every frame the processor pushed downstream (with
the framework's own Start/End frames filtered out), so tests can assert on what
the firewall emitted.

This is built on Pipecat's own test primitives (``QueuedFrameProcessor``,
``Pipeline``, ``PipelineTask``) rather than poking processor internals.
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
from pipecat.tests.utils import QueuedFrameProcessor


async def _pump(processor: FrameProcessor, frames: Sequence[Frame]) -> list[Frame]:
    """Send ``frames`` through ``processor``; return downstream frames it pushed."""
    received: asyncio.Queue[Frame] = asyncio.Queue()
    sink = QueuedFrameProcessor(
        queue=received,
        queue_direction=FrameDirection.DOWNSTREAM,
        ignore_start=True,
    )
    pipeline = Pipeline([processor, sink])
    task = PipelineTask(pipeline, params=PipelineParams(), cancel_on_idle_timeout=False)

    async def feed() -> None:
        await asyncio.sleep(0.01)  # let the runner start
        for frame in frames:
            await task.queue_frame(frame)
        await task.queue_frame(EndFrame())

    runner = PipelineRunner()
    await asyncio.gather(runner.run(task), feed())

    out: list[Frame] = []
    while not received.empty():
        frame = await received.get()
        if isinstance(frame, (StartFrame, EndFrame)):
            continue
        out.append(frame)
    return out


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
