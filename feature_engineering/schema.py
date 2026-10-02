"""Canonical 24-feature schema constants for Module 4.

Re-exported from :mod:`feature_engineering.contract`, the verified
training/live feature contract. Do not rename, reorder, add, or remove entries.
"""

from __future__ import annotations

from feature_engineering.contract import (
    ACTIVITY_TIMEOUT_SECONDS,
    FEATURE_COUNT,
    FEATURE_ORDER,
    INTEGER_FEATURES,
)

__all__ = [
    "ACTIVITY_TIMEOUT_SECONDS",
    "FEATURE_COUNT",
    "FEATURE_ORDER",
    "INTEGER_FEATURES",
]
