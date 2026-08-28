"""Feature Engineering — Module 4 of the MLCN cybersecurity project."""

from feature_engineering.engine import (
    FeatureEngineeringEngine,
    compute_feature_map,
    extract_features,
)
from feature_engineering.models import FeatureVector
from feature_engineering.schema import (
    ACTIVITY_TIMEOUT_SECONDS,
    FEATURE_COUNT,
    FEATURE_ORDER,
)

__all__ = [
    "ACTIVITY_TIMEOUT_SECONDS",
    "FEATURE_COUNT",
    "FEATURE_ORDER",
    "FeatureEngineeringEngine",
    "FeatureVector",
    "compute_feature_map",
    "extract_features",
]
__version__ = "1.0.0"
