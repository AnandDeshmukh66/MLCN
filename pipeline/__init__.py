"""MLCN end-to-end pipeline — orchestration for Modules 1–5."""

from pipeline.engine import IntrusionDetectionPipeline
from pipeline.models import PipelineResult

__all__ = [
    "IntrusionDetectionPipeline",
    "PipelineResult",
]
__version__ = "1.0.0"
