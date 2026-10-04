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

# Lab wire shapes. Each profile's per-connection packet pattern is chosen so the
# captured CIC flow resembles the training class (validated by
# tests/test_profile_validation.py). They are still rate-limited by the caps above.

# Closed ports on Windows answer SYN with RST, but connect() retransmits the SYN
# every ~0.5 s; giving up earlier keeps one SYN/RST pair per probe (CIC PortScan).
PORT_SCAN_PROBE_TIMEOUT_SECONDS = 0.15

# Brute Force: one TCP session with several short request/deny line exchanges
# (FTP-Patator-like). Server reply delay and client think time both exceed the
# 200 ms delayed-ACK timer so each data segment gets its own pure ACK.
BRUTE_FORCE_ATTEMPTS_PER_SESSION = 6
BRUTE_FORCE_ATTEMPT_PREFIX = b"LAB-AUTH "
BRUTE_FORCE_DENY_LINE = b"530 LAB DENIED\r\n"
BRUTE_FORCE_REPLY_DELAY_SECONDS = (0.3, 0.5)
BRUTE_FORCE_THINK_SECONDS = (0.3, 0.8)
BRUTE_FORCE_SESSION_TIMEOUT_SECONDS = 5.0

# DDoS (LOIC) and DoS (Hulk) training flows fetch the victim's ~11.6 KB default
# page; DDoS uses a tiny request, DoS a full-header browser-like request.
LAB_PAGE_PATHS = (b"/ddos", b"/lab/dos")
LAB_PAGE_RESPONSE_BYTES = 11_600
DDOS_REQUEST = b"GET /ddos HTTP/1.0\r\n\r\n"
DOS_REQUEST_BYTES = 330
