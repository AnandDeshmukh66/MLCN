"""End-to-end pipeline result for the integrated MLCN detection path."""

from __future__ import annotations

from dataclasses import dataclass

from feature_engineering.models import FeatureVector
from flow_builder.models import Flow
from ml_detection.models import DetectionResult


@dataclass(frozen=True)
class PipelineResult:
    """
    One completed flow after Modules 3 → 4 → 5.

    Preserves the flow, the 24-feature vector, and the XGBoost detection
    so callers can log, store, or forward results without re-running stages.
    """

    flow: Flow
    features: FeatureVector
    detection: DetectionResult
    # True when ``detection`` is the temporary demo display (demo_fallback package);
    # ``genuine_detection`` then holds the untouched XGBoost output.
    demo_fallback: bool = False
    genuine_detection: DetectionResult | None = None

    @property
    def model_detection(self) -> DetectionResult:
        """The real XGBoost output, regardless of any demo display override."""
        return self.genuine_detection or self.detection

    @property
    def predicted_class(self) -> str:
        return self.detection.predicted_class

    @property
    def confidence(self) -> float:
        return self.detection.confidence

    def as_dict(self) -> dict[str, object]:
        genuine = self.model_detection
        return {
            "protocol": self.flow.protocol,
            "src_ip": self.flow.src_ip,
            "dst_ip": self.flow.dst_ip,
            "src_port": self.flow.src_port,
            "dst_port": self.flow.dst_port,
            "packet_count": self.flow.packet_count,
            "byte_count": self.flow.byte_count,
            "duration": self.flow.duration,
            "start_time": self.flow.start_time.timestamp(),
            "first_packet_flags": self.flow.packets[0].tcp_flags if self.flow.packets else None,
            "predicted_class": self.detection.predicted_class,
            "predicted_class_id": self.detection.predicted_class_id,
            "confidence": self.detection.confidence,
            "probabilities": dict(self.detection.probabilities),
            "demo_fallback": self.demo_fallback,
            "genuine_predicted_class": genuine.predicted_class,
            "genuine_confidence": genuine.confidence,
            "genuine_probabilities": dict(genuine.probabilities),
        }

    def __repr__(self) -> str:
        return (
            f"PipelineResult(protocol={self.flow.protocol!r}, "
            f"packets={self.flow.packet_count}, "
            f"predicted_class={self.detection.predicted_class!r}, "
            f"confidence={self.detection.confidence:.4f})"
        )
