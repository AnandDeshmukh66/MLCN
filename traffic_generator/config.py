"""Configuration and safety limits for the MLCN traffic generator."""

from __future__ import annotations

from pathlib import Path

# Repository root (parent of traffic_generator package).
REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PROFILES_PATH = REPO_ROOT / "assets" / "MLCN_compact_attack_traffic_profiles.json"
DEFAULT_LOG_DIR = REPO_ROOT / "logs" / "traffic_generator"

# Laboratory-only hard caps (conservative; independent of UI intensity).
MAX_TEST_DURATION_SECONDS = 300.0
MAX_CONNECTION_RATE_PER_SEC = 20.0
MAX_PACKET_RATE_PER_SEC = 50.0
MAX_CONCURRENT_CONNECTIONS = 10
MAX_PORT_SCAN_PORTS = 50
MAX_PAYLOAD_BYTES = 512

# Default receiver service ports probed / used in lab tests.
DEFAULT_HTTP_PORT = 8080
DEFAULT_ALT_PORTS = (8080, 8081, 8082, 9090)

# Profile names matching the XGBoost model / profile JSON.
PROFILE_NAMES: tuple[str, ...] = (
    "BENIGN",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scan",
)

# CICFlowMeter-style feature units in the profile JSON are microseconds for time fields.
PROFILE_TIME_UNIT_MICROSECONDS = 1_000_000.0
