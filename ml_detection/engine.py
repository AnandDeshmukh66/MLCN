"""Machine Learning Detection Engine — Module 5 of the MLCN pipeline.

Loads the trained XGBoost multi-class IDS model and maps Module 4
``FeatureVector`` values to a ``DetectionResult``.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Iterable, Sequence, Union

import numpy as np
import xgboost as xgb

from feature_engineering.models import FeatureVector
from feature_engineering.schema import FEATURE_COUNT, FEATURE_ORDER

from ml_detection.models import DetectionResult
from ml_detection.schema import (
    CLASS_COUNT,
    CLASS_ORDER,
    DEFAULT_FEATURES_META_PATH,
    DEFAULT_MODEL_PATH,
    ID_TO_CLASS,
)

logger = logging.getLogger(__name__)

FeatureInput = Union[FeatureVector, Sequence[float]]


class ModelLoadError(RuntimeError):
    """Raised when the XGBoost model or its metadata cannot be loaded."""


class FeatureValidationError(ValueError):
    """Raised when an input feature vector is incompatible with the model."""


def _is_finite_number(value: object) -> bool:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return math.isfinite(number)


def validate_feature_values(
    values: Sequence[float],
    *,
    expected_count: int = FEATURE_COUNT,
) -> tuple[float, ...]:
    """
    Validate a raw numeric feature sequence for inference.

    Ensures exact length, numeric types, and finite values.
    """
    if not isinstance(values, (list, tuple)):
        # Allow FeatureVector / other sequences via list copy below.
        try:
            values = list(values)
        except TypeError as exc:
            raise FeatureValidationError(
                f"features must be a sequence of numbers, got {type(values).__name__}"
            ) from exc

    if len(values) != expected_count:
        raise FeatureValidationError(
            f"expected exactly {expected_count} features, got {len(values)}"
        )

    normalized: list[float] = []
    for index, raw in enumerate(values):
        if not _is_finite_number(raw):
            raise FeatureValidationError(
                f"feature at index {index} ({FEATURE_ORDER[index]!r}) "
                f"must be a finite number, got {raw!r}"
            )
        normalized.append(float(raw))
    return tuple(normalized)


def validate_feature_vector(features: FeatureInput) -> tuple[float, ...]:
    """Accept a Module 4 ``FeatureVector`` or a length-24 numeric sequence."""
    if isinstance(features, FeatureVector):
        if list(features.names) != list(FEATURE_ORDER):
            raise FeatureValidationError(
                "FeatureVector feature order does not match the common schema"
            )
        return validate_feature_values(features.values)

    if isinstance(features, (str, bytes, bytearray, dict)):
        raise FeatureValidationError(
            f"features must be FeatureVector or a numeric sequence, "
            f"got {type(features).__name__}"
        )

    return validate_feature_values(features)


def _load_features_metadata(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModelLoadError(f"features metadata not found: {path}") from exc
    except OSError as exc:
        raise ModelLoadError(f"failed to read features metadata: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ModelLoadError(f"invalid features metadata JSON: {path}") from exc

    meta_features = payload.get("features")
    meta_classes = payload.get("classes")
    if not isinstance(meta_features, list) or not isinstance(meta_classes, list):
        raise ModelLoadError(
            f"features metadata missing 'features'/'classes' lists: {path}"
        )
    if meta_features != list(FEATURE_ORDER):
        raise ModelLoadError(
            "model feature order does not match Module 4 FEATURE_ORDER / "
            "data/common_feature_schema.json"
        )
    if meta_classes != list(CLASS_ORDER):
        raise ModelLoadError(
            "model class order does not match Module 5 CLASS_ORDER"
        )
    return payload


def _load_booster(model_path: Path) -> xgb.Booster:
    if not model_path.is_file():
        raise ModelLoadError(f"XGBoost model file not found: {model_path}")
    try:
        booster = xgb.Booster()
        booster.load_model(str(model_path))
    except Exception as exc:  # noqa: BLE001 - surface any load failure clearly
        raise ModelLoadError(f"failed to load XGBoost model from {model_path}: {exc}") from exc

    booster_features = list(booster.feature_names or [])
    if booster_features and booster_features != list(FEATURE_ORDER):
        raise ModelLoadError(
            "loaded booster feature_names do not match the common feature schema"
        )
    return booster


def _best_iteration(booster: xgb.Booster) -> int:
    attrs = booster.attributes()
    if "best_iteration" in attrs:
        return int(attrs["best_iteration"])
    # Fallback: last completed round index.
    rounds = int(booster.num_boosted_rounds())
    return max(0, rounds - 1)


class MLDetectionEngine:
    """
    Inference-only XGBoost multi-class IDS detector.

    Consumes Module 4 ``FeatureVector`` instances (24 schema-ordered floats)
    and returns ``DetectionResult`` values for the five trained classes.
    """

    def __init__(
        self,
        model_path: str | Path | None = None,
        features_meta_path: str | Path | None = None,
    ) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.features_meta_path = (
            Path(features_meta_path) if features_meta_path else DEFAULT_FEATURES_META_PATH
        )

        self._metadata = _load_features_metadata(self.features_meta_path)
        self._booster = _load_booster(self.model_path)
        self._best_iteration = _best_iteration(self._booster)

        logger.debug(
            "MLDetectionEngine ready model=%s best_iteration=%s classes=%s",
            self.model_path,
            self._best_iteration,
            CLASS_ORDER,
        )

    @property
    def classes(self) -> tuple[str, ...]:
        return CLASS_ORDER

    @property
    def feature_names(self) -> tuple[str, ...]:
        return FEATURE_ORDER

    @property
    def best_iteration(self) -> int:
        return self._best_iteration

    def predict(self, features: FeatureInput) -> DetectionResult:
        """Run XGBoost inference on one feature vector."""
        values = validate_feature_vector(features)
        matrix = np.asarray([values], dtype=np.float32)
        dmatrix = xgb.DMatrix(matrix, feature_names=list(FEATURE_ORDER))

        try:
            proba = self._booster.predict(
                dmatrix,
                iteration_range=(0, self._best_iteration + 1),
            )
        except Exception:
            logger.debug("XGBoost predict failed", exc_info=True)
            raise

        if proba.ndim == 1:
            row = proba
        else:
            row = proba[0]

        if len(row) != CLASS_COUNT:
            raise RuntimeError(
                f"model returned {len(row)} class probabilities, expected {CLASS_COUNT}"
            )

        probabilities = {
            CLASS_ORDER[index]: float(row[index]) for index in range(CLASS_COUNT)
        }
        predicted_id = int(np.argmax(row))
        predicted_class = ID_TO_CLASS[predicted_id]
        confidence = float(row[predicted_id])

        return DetectionResult(
            predicted_class=predicted_class,
            predicted_class_id=predicted_id,
            confidence=confidence,
            probabilities=probabilities,
        )

    def predict_many(self, feature_rows: Iterable[FeatureInput]) -> list[DetectionResult]:
        """Run inference on many feature vectors, preserving order."""
        return [self.predict(row) for row in feature_rows]

    def try_predict(self, features: FeatureInput) -> DetectionResult | None:
        """
        Predict while suppressing unexpected runtime failures.

        Validation errors (bad feature count/type) still propagate. Model/runtime
        errors are logged at DEBUG and yield ``None`` so a live pipeline can continue.
        """
        values = validate_feature_vector(features)
        try:
            return self.predict(values)
        except FeatureValidationError:
            raise
        except Exception:
            logger.debug("try_predict suppressed failure", exc_info=True)
            return None


def predict(
    features: FeatureInput,
    *,
    model_path: str | Path | None = None,
    features_meta_path: str | Path | None = None,
) -> DetectionResult:
    """Convenience one-shot prediction (loads the model on each call)."""
    engine = MLDetectionEngine(
        model_path=model_path,
        features_meta_path=features_meta_path,
    )
    return engine.predict(features)


# Re-export mapping helpers for callers / tests.
__all__ = [
    "CLASS_COUNT",
    "CLASS_ORDER",
    "CLASS_TO_ID",
    "FeatureValidationError",
    "ID_TO_CLASS",
    "MLDetectionEngine",
    "ModelLoadError",
    "predict",
    "validate_feature_vector",
    "validate_feature_values",
]
