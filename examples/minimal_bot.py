"""Minimal Pipecat voice bot with pipecat-firewall added in one line.

The headline: dropping ``SentryFirewall()`` into the pipeline — right after STT,
before the user context aggregator — blocks adversarial input before the LLM
ever sees it, and speaks a deterministic refusal instead.

Running it for real needs a transport + STT/LLM/TTS services and their API keys:

    pip install "pipecat-ai[daily,deepgram,openai,cartesia]"
    export DEEPGRAM_API_KEY=... OPENAI_API_KEY=... CARTESIA_API_KEY=... DAILY_API_KEY=...
    python examples/minimal_bot.py

The service imports live inside ``main()`` on purpose, so this file imports
cleanly (for a smoke test) even when only ``pipecat-firewall`` + ``pipecat-ai``
core are installed.
"""

from __future__ import annotations

import asyncio
import os

from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.runner import PipelineRunner
from pipecat.pipeline.task import PipelineTask

from pipecat_firewall import SentryDetectionFrame, SentryFirewall


async def main() -> None:
    # Optional service plugins — imported lazily so module import stays light.
    from pipecat.audio.vad.silero import SileroVADAnalyzer
    from pipecat.services.cartesia.tts import CartesiaTTSService
    from pipecat.services.deepgram.stt import DeepgramSTTService
    from pipecat.services.openai.llm import OpenAILLMService
    from pipecat.transports.services.daily import DailyParams, DailyTransport

    transport = DailyTransport(
        room_url=os.environ["DAILY_ROOM_URL"],
        token=os.environ.get("DAILY_TOKEN"),
        bot_name="Firewall Demo",
        params=DailyParams(audio_in_enabled=True, audio_out_enabled=True, vad_analyzer=SileroVADAnalyzer()),
    )
    stt = DeepgramSTTService(api_key=os.environ["DEEPGRAM_API_KEY"])
    llm = OpenAILLMService(api_key=os.environ["OPENAI_API_KEY"], model="gpt-4o-mini")
    tts = CartesiaTTSService(api_key=os.environ["CARTESIA_API_KEY"], voice_id="...")

    context = llm.create_context_aggregator(
        [{"role": "system", "content": "You are a helpful bank support agent."}]
    )

    firewall = SentryFirewall()  # ← detects & blocks adversarial input

    @firewall.event_handler("on_detection")
    async def _(proc: SentryFirewall, detection) -> None:  # noqa: ANN001
        print(f"[firewall] blocked {detection.category.value}: {detection.matched_text!r}")

    pipeline = Pipeline(
        [
            transport.input(),
            stt,
            firewall,  # after STT, before the user context aggregator
            context.user(),
            llm,
            tts,
            transport.output(),
            context.assistant(),
        ]
    )

    task = PipelineTask(pipeline)
    await PipelineRunner().run(task)


# Re-exported so an import-only smoke test can reference the wired-in symbols
# without needing any service keys.
__all__ = ["main", "SentryFirewall", "SentryDetectionFrame"]


if __name__ == "__main__":
    asyncio.run(main())
