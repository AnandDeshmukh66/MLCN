"""Canonical 24-feature schema constants for Module 4.

Order and semantics match ``data/common_feature_schema.json`` exactly.
Do not rename, reorder, add, or remove entries.
"""

from __future__ import annotations

# CICFlowMeter default activity timeout (5_000_000 microseconds).
ACTIVITY_TIMEOUT_SECONDS = 5.0

# Exact retained feature order expected by the MLCN XGBoost detection engine.
FEATURE_ORDER: tuple[str, ...] = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Active Mean",
    "Idle Mean",
)

FEATURE_COUNT = len(FEATURE_ORDER)

# Integer-typed features per schema (others are float).
INTEGER_FEATURES: frozenset[str] = frozenset(
    {
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packets Length Total",
        "Bwd Packets Length Total",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
    }
)
