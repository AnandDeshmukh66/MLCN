# MLCN — Module 2: Packet Parsing

Formal packet parsing, normalization, validation, and structured-output layer
for the MLCN pipeline.

```text
Network → Module 1: Packet Capture → Module 2: Packet Parsing → Module 3: Flow Builder
```

## Responsibility

Module 2 takes raw packets produced by Module 1 (Scapy `Packet` objects) and
emits a clean, typed `PacketMetadata` value suitable as direct input to
Module 3 (Flow Builder). It does **not** capture or sniff traffic.

Parsed fields:

| Field | Notes |
|-------|--------|
| `timestamp` | Timezone-aware UTC `datetime` |
| `src_ip` / `dst_ip` | Canonical IP strings, or `None` if absent |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `Other` |
| `src_port` / `dst_port` | Set for TCP/UDP; otherwise `None` |
| `length` | Non-negative packet length |
| `tcp_flags` | Compact flag string (e.g. `SA`); `None` if not TCP |
| `ttl` | IPv4 TTL or IPv6 hop limit; `None` if not IP |
| `tcp_window` | TCP window size; `None` if not TCP |

Malformed or unexpected inputs return `None` instead of raising.

## Integration with Module 1

Module 1 still owns live capture and the CLI. Its parse path delegates to
Module 2, then maps `PacketMetadata` → `ParsedPacket` for the existing
tabular display.

Programmatic pipeline path (with Module 3 Flow Builder):

```python
from packet_capture import PacketCaptureEngine
from packet_parsing import PacketMetadata
from flow_builder import FlowBuilder

engine = PacketCaptureEngine(interface="lo0")
builder = FlowBuilder(inactivity_timeout=60.0)

def on_packet(meta: PacketMetadata) -> None:
    for flow in builder.add_packet(meta):
        print(flow.protocol, flow.packet_count, flow.duration)

engine.capture_metadata(on_packet)
# or: for meta in engine.iter_metadata(): ...
```

Standalone parsing (tests / offline):

```python
from packet_parsing import parse_packet, PacketMetadata
```

## Test / run

From the project root:

```bash
source macvenv/bin/activate   # or your venv
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Live capture CLI (unchanged Module 1 entry point):

```bash
sudo python -m packet_capture -i lo0
```
