# MLCN — Module 1: Live Packet Capture Engine

Real-time network packet capture for the host using Python and Scapy. This module extracts timestamp, protocol, IP addresses, ports, packet length, and TCP flags, then prints each packet in a fixed-width log format.

## Requirements

- Python 3.10+
- **macOS / Linux:** capture usually requires elevated privileges (`sudo`)
- **Windows:** install [Npcap](https://nmap.org/npcap/) (with WinPcap compatibility mode enabled), then run the terminal as Administrator

## Install dependencies

From the project root (`MLCN/`):

```bash
cd /Users/anand/Desktop/Anand/MLCN
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## List network interfaces

```bash
python -m packet_capture --list-interfaces
```

Example output:

```text
INTERFACE            ADDRESS
----------------------------------------
lo0                  127.0.0.1
en0                  192.168.1.42
```

Use the interface that carries the traffic you want to observe. For local HTTP server testing, **`lo0`** (macOS) or **`lo`** (Linux) is the right choice.

## Start packet capture

**Terminal 1 — capture (macOS/Linux example using loopback):**

```bash
source .venv/bin/activate
sudo python -m packet_capture -i lo0
```

**Windows (Administrator PowerShell):**

```powershell
.\.venv\Scripts\activate
python -m packet_capture -i "\Device\NPF_Loopback"
```

If you omit `-i`, Scapy uses its default interface:

```bash
sudo python -m packet_capture
```

Expected startup output:

```text
Starting live capture on interface: lo0
Press Ctrl+C to stop.

TIMESTAMP                  PROTO  SRC IP           DST IP           SRC PORT  DST PORT  LEN    TCP FLAGS
----------------------------------------------------------------------------------------------------------
```

Press **Ctrl+C** to stop gracefully. A summary line is printed when capture ends.

## Start a local traffic source

**Terminal 2 — simple Python HTTP server on port 8080:**

```bash
cd /Users/anand/Desktop/Anand/MLCN
python3 -m http.server 8080
```

Alternative (FastAPI):

```bash
pip install fastapi uvicorn
uvicorn --host 127.0.0.1 --port 8080 --app-dir . "path.to:app"   # if you add a small app later
```

For Module 1 testing, `python3 -m http.server 8080` is sufficient.

## Generate traffic

**Terminal 3 — send requests (any one of these):**

```bash
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/README.md
```

Or open `http://127.0.0.1:8080/` in a browser, or send a GET request from Postman to `http://127.0.0.1:8080/`.

## Verify captured packets

In **Terminal 1**, you should see rows like:

```text
2026-07-25 06:55:01.123    TCP    127.0.0.1        127.0.0.1        54321     8080      74     S
2026-07-25 06:55:01.124    TCP    127.0.0.1        127.0.0.1        8080      54321     74     SA
2026-07-25 06:55:01.125    TCP    127.0.0.1        127.0.0.1        54321     8080      52     A
```

What to confirm:

| Field | Expected for local HTTP test |
|-------|------------------------------|
| Protocol | `TCP` for HTTP traffic |
| SRC/DST IP | `127.0.0.1` on loopback |
| DST PORT | `8080` on request packets to the server |
| LEN | Non-zero packet length |
| TCP FLAGS | Handshake flags such as `S`, `SA`, `A`; `-` for non-TCP |

If nothing appears:

1. Confirm capture is on the **same interface** as the traffic (`lo0` / `lo` for localhost).
2. Confirm capture is running with **sudo** (or Administrator on Windows).
3. Re-run `curl http://127.0.0.1:8080/` while capture is active.

## CLI reference

```text
python -m packet_capture [-h] [-i INTERFACE] [-l] [-v]

  -i, --interface       Interface to capture on
  -l, --list-interfaces List interfaces and exit
  -v, --verbose         Debug logging
```

## Project layout

```text
MLCN/
├── requirements.txt
├── README.md
├── packet_capture/       # Module 1 — live capture + CLI display
└── packet_parsing/       # Module 2 — parse / normalize / PacketMetadata
```

## Programmatic usage

```python
from packet_capture import PacketCaptureEngine

engine = PacketCaptureEngine(interface="lo0")
engine.start()
```

## Notes

- Malformed or unsupported packets are skipped silently (use `-v` for debug traces).
- Field parsing is performed by **Module 2** (`packet_parsing`); this module owns capture and display only.
- No flow building, ML, database, or dashboard code is included.
- PyShark is not required; Scapy is the sole capture backend.
