"""Detection result model for Module 5 of the MLCN pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Mapping

from ml_detection.schema import CLASS_COUNT, CLASS_ORDER, CLASS_TO_ID


@dataclass(frozen=True)
class DetectionResult:
    """
    Multi-class IDS prediction produced by the Module 5 XGBoost engine.

    ``probabilities`` maps every class name in ``CLASS_ORDER`` to its
    softmax probability. ``confidence`` is the probability of ``predicted_class``.
    """

    predicted_class: str
    predicted_class_id: int
    confidence: float
    probabilities: dict[str, float]

    def __post_init__(self) -> None:
        if self.predicted_class not in CLASS_TO_ID:
            raise ValueError(f"unknown predicted_class: {self.predicted_class!r}")
        if self.predicted_class_id != CLASS_TO_ID[self.predicted_class]:
            raise ValueError(
                "predicted_class_id does not match predicted_class: "
                f"{self.predicted_class_id} vs {self.predicted_class!r}"
            )
        if len(self.probabilities) != CLASS_COUNT:
            raise ValueError(
                f"probabilities must contain {CLASS_COUNT} classes, "
                f"got {len(self.probabilities)}"
            )
        for name in CLASS_ORDER:
            if name not in self.probabilities:
                raise ValueError(f"probabilities missing class {name!r}")

    @property
    def class_order(self) -> tuple[str, ...]:
        return CLASS_ORDER

    def probability_vector(self) -> tuple[float, ...]:
        """Return class probabilities in ``CLASS_ORDER``."""
        return tuple(self.probabilities[name] for name in CLASS_ORDER)

    def as_dict(self) -> dict[str, object]:
        return {
            "predicted_class": self.predicted_class,
            "predicted_class_id": self.predicted_class_id,
            "confidence": self.confidence,
            "probabilities": dict(self.probabilities),
        }

    def items(self) -> Iterator[tuple[str, float]]:
        for name in CLASS_ORDER:
            yield name, self.probabilities[name]

    @classmethod
    def from_probability_mapping(
        cls,
        probabilities: Mapping[str, float],
    ) -> DetectionResult:
        """Build a result by taking the argmax over a class→probability map."""
        missing = [name for name in CLASS_ORDER if name not in probabilities]
        if missing:
            raise ValueError(f"probabilities missing classes: {missing}")
        best_name = max(CLASS_ORDER, key=lambda name: float(probabilities[name]))
        best_id = CLASS_TO_ID[best_name]
        conf = float(probabilities[best_name])
        return cls(
            predicted_class=best_name,
            predicted_class_id=best_id,
            confidence=conf,
            probabilities={name: float(probabilities[name]) for name in CLASS_ORDER},
        )

    def __repr__(self) -> str:
        return (
            f"DetectionResult(predicted_class={self.predicted_class!r}, "
            f"predicted_class_id={self.predicted_class_id}, "
            f"confidence={self.confidence:.6f})"
        )
