"""Load MLCN compact attack traffic profiles from JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from traffic_generator.config import DEFAULT_PROFILES_PATH, PROFILE_NAMES


class ProfileLoadError(RuntimeError):
    """Raised when the profile JSON cannot be loaded or parsed."""


def load_profiles(path: Path | None = None) -> dict[str, Any]:
    """Load and return the full profiles document."""
    profile_path = path or DEFAULT_PROFILES_PATH
    if not profile_path.is_file():
        raise ProfileLoadError(f"profile file not found: {profile_path}")
    try:
        return json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileLoadError(f"invalid profile JSON: {profile_path}") from exc
    except OSError as exc:
        raise ProfileLoadError(f"failed to read profile file: {profile_path}") from exc


def list_profile_names(document: dict[str, Any] | None = None) -> list[str]:
    """Return available IDS test profile names in stable order."""
    doc = document or load_profiles()
    names: list[str] = ["BENIGN"]
    attack_profiles = doc.get("attack_profiles", {})
    for name in PROFILE_NAMES:
        if name == "BENIGN":
            continue
        if name in attack_profiles:
            names.append(name)
    return names


def get_attack_profile(document: dict[str, Any], profile_name: str) -> dict[str, Any]:
    """Return one attack profile block (raises for BENIGN — use benign_baseline)."""
    if profile_name == "BENIGN":
        raise KeyError("BENIGN uses benign_baseline, not attack_profiles")
    profiles = document.get("attack_profiles", {})
    if profile_name not in profiles:
        raise KeyError(f"unknown profile: {profile_name!r}")
    return profiles[profile_name]


def _percentile_value(block: dict[str, Any], key: str = "median") -> float:
    if key in block:
        value = block[key]
        return float(value) if value is not None else 0.0
    target = block.get("target_distribution", {})
    percentiles = target.get("target_percentiles", {})
    if key in percentiles:
        value = percentiles[key]
        return float(value) if value is not None else 0.0
    return 0.0


def extract_reference_features(
    document: dict[str, Any],
    profile_name: str,
) -> dict[str, float]:
    """
    Pull empirical reference medians from the profile JSON for logging/comparison.

    Does NOT produce ML features — reference only.
    """
    if profile_name == "BENIGN":
        baseline = document.get("benign_baseline", {})
        return {name: _percentile_value(stats) for name, stats in baseline.items()}

    profile = get_attack_profile(document, profile_name)
    refs: dict[str, float] = {}
    for item in profile.get("top_discriminative_features", []):
        feature = item.get("feature")
        if not feature:
            continue
        attack_median = item.get("attack_median")
        if attack_median is not None:
            refs[str(feature)] = float(attack_median)
            continue
        target = item.get("target_distribution", {})
        percentiles = target.get("target_percentiles", {})
        if "median" in percentiles and percentiles["median"] is not None:
            refs[str(feature)] = float(percentiles["median"])
    return refs


def feature_value_from_profile(
    document: dict[str, Any],
    profile_name: str,
    feature_name: str,
    *,
    percentile: str = "median",
) -> float:
    """Read one empirical percentile for a named feature from the profile JSON."""
    if profile_name == "BENIGN":
        baseline = document.get("benign_baseline", {})
        if feature_name not in baseline:
            return 0.0
        return _percentile_value(baseline[feature_name], percentile)

    profile = get_attack_profile(document, profile_name)
    for item in profile.get("top_discriminative_features", []):
        if item.get("feature") != feature_name:
            continue
        target = item.get("target_distribution", {})
        percentiles = target.get("target_percentiles", {})
        if percentile in percentiles and percentiles[percentile] is not None:
            return float(percentiles[percentile])
        attack_median = item.get("attack_median")
        if attack_median is not None:
            return float(attack_median)
    return 0.0
