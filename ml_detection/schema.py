"""Class labels and model artifact paths for Module 5."""

from __future__ import annotations

from pathlib import Path

# Repository root (parent of the ``ml_detection`` package).
REPO_ROOT = Path(__file__).resolve().parents[1]

# Prefer ``models/`` (does not shadow the pip ``xgboost`` package). Fall back to
# ``xgboost/`` for Windows deployments that still keep the original folder name.
_ARTIFACT_DIR_CANDIDATES: tuple[str, ...] = ("models", "xgboost")


def resolve_artifact_path(filename: str) -> Path:
    """
    Resolve a model artifact under ``models/`` or ``xgboost/``.

    Returns the first existing file. If neither exists, returns the preferred
    ``models/`` path so load errors name the expected location.
    """
    preferred = REPO_ROOT / "models" / filename
    for folder in _ARTIFACT_DIR_CANDIDATES:
        candidate = REPO_ROOT / folder / filename
        if candidate.is_file():
            return candidate
    return preferred


DEFAULT_MODEL_PATH = resolve_artifact_path("xgboost_ids_multiclass.json")
DEFAULT_FEATURES_META_PATH = resolve_artifact_path("xgboost_ids_features.json")

# Exact class order matching model feature metadata / training.
CLASS_ORDER: tuple[str, ...] = (
    "BENIGN",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scan",
)

CLASS_COUNT = len(CLASS_ORDER)

CLASS_TO_ID: dict[str, int] = {name: index for index, name in enumerate(CLASS_ORDER)}
ID_TO_CLASS: dict[int, str] = {index: name for index, name in enumerate(CLASS_ORDER)}
