"""Machine Learning Detection — Module 5 of the MLCN cybersecurity project."""

from ml_detection.engine import (
    FeatureValidationError,
    MLDetectionEngine,
    ModelLoadError,
    predict,
    validate_feature_vector,
    validate_feature_values,
)
from ml_detection.models import DetectionResult
from ml_detection.schema import (
    CLASS_COUNT,
    CLASS_ORDER,
    CLASS_TO_ID,
    DEFAULT_FEATURES_META_PATH,
    DEFAULT_MODEL_PATH,
    ID_TO_CLASS,
)

__all__ = [
    "CLASS_COUNT",
    "CLASS_ORDER",
    "CLASS_TO_ID",
    "DEFAULT_FEATURES_META_PATH",
    "DEFAULT_MODEL_PATH",
    "DetectionResult",
    "FeatureValidationError",
    "ID_TO_CLASS",
    "MLDetectionEngine",
    "ModelLoadError",
    "predict",
    "validate_feature_vector",
    "validate_feature_values",
]
__version__ = "1.0.0"
