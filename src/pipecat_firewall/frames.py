"""Downstream event frame for firewall detections.

``SentryDetectionFrame`` is pushed downstream whenever the firewall acts on a
turn, so any consumer (metrics, logging, or the existing SENTRY dashboard) can
visualize firewall events. It's a plain :class:`DataFrame` carrying the
:class:`Detection` and the :class:`Mode` that was applied; processors that don't
recognize it pass it through untouched, so it's safe to emit into any pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass

from pipecat.frames.frames import DataFrame

from .types import Detection, Mode


@dataclass
class SentryDetectionFrame(DataFrame):
    """Emitted downstream when the firewall flags, blocks, or redacts a turn.

    Attributes:
        detection: The detection that fired.
        mode: The enforcement mode that was applied to it.
    """

    detection: Detection
    mode: Mode
