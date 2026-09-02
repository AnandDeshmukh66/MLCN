# MLCN Controlled IDS Traffic Generator

Laboratory-only test traffic generator for the MLCN receiver pipeline (Modules 1–5).
This package is **completely separate** from the receiver/detection modules.

```text
UI (Streamlit)
  → Profile Selector (MLCN_compact_attack_traffic_profiles.json)
  → Parameter Translator
  → Safe Traffic Generator (socket/HTTP, rate-limited)
  → Receiver Laptop (M1→M5) → XGBoost → Classification
```

## Safety

- Private/local targets only (`127.0.0.0/8`, RFC1918, link-local)
- Public Internet addresses are rejected
- Hard caps on duration, connection rate, packet rate, port-scan span
- Mandatory `LAB` confirmation before start
- Immediate Stop control
- No credentials, flooding, stealth, or evasion

## Install

From the project root:

```bash
pip install -r requirements.txt
```

## Run the UI

```bash
streamlit run traffic_generator/streamlit_app.py
```

Or:

```bash
python -m traffic_generator
```

## Two-machine laboratory setup (recommended)

**Laptop B — Receiver (existing M1→M5, unchanged):**

```bash
python -m pipeline -l
python -m traffic_generator.receiver_server --port 8080
python -m pipeline -i "Wi-Fi,\Device\NPF_Loopback" --lab-port 8080
```

Use the exact Npcap interface name from `-l`. On Windows, capture **both** Wi-Fi and
`\Device\NPF_Loopback` — traffic to this PC's own IP is often hairpinned and never
appears on Wi-Fi, while unrelated outbound HTTPS (`:443`) still does. `--lab-port 8080`
filters out that background noise.

**Laptop A — Generator (this package):**

1. Open the Streamlit UI on a **different machine** from Laptop B
2. Select profile (`BENIGN`, `Brute Force`, `DDoS`, `DoS`, `Port Scan`)
3. Enter Laptop B's **private IP** (e.g. `192.168.x.x`) — not Laptop A's IP
4. Confirm with checkbox + type `LAB`
5. Start test → observe classifications on Laptop B terminal

Traffic must be **destined to Laptop B** (same Wi-Fi is not enough for passive sniffing of third-party flows).

**Do not** target this PC's own LAN IP from the same machine without Validation mode — use Validation mode for single-host tests instead.

## Single-machine validation mode

Enable **Validation mode** in the UI (loopback only):

- Starts a tiny lab echo HTTP server (generator side)
- Starts receiver `IntrusionDetectionPipeline` on loopback in a background thread
- Records: target profile → observed 24 features → XGBoost prediction

Requires Npcap (Windows) or elevated privileges (macOS/Linux) for loopback capture.

## Profile source of truth

`assets/MLCN_compact_attack_traffic_profiles.json`

Parameters are derived from empirical medians — the generator never writes the 24 ML features directly.

## Logs

Session logs: `logs/traffic_generator/run_<profile>_<timestamp>.json`
