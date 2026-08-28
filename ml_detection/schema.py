"""Class labels and model artifact paths for Module 5."""

from __future__ import annotations

from pathlib import Path

# Repository root (parent of the ``ml_detection`` package).
REPO_ROOT = Path(__file__).resolve().parents[1]

# Trained artifacts live under ``models/`` (not ``xgboost/``) so the directory
# does not shadow the pip ``xgboost`` package on ``sys.path``.
DEFAULT_MODEL_PATH = REPO_ROOT / "models" / "xgboost_ids_multiclass.json"
DEFAULT_FEATURES_META_PATH = REPO_ROOT / "models" / "xgboost_ids_features.json"

# Exact class order matching ``models/xgboost_ids_features.json`` / training.
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
