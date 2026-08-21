# MLCN — Module 3: Flow Builder

Bidirectional flow assembly for the MLCN pipeline.

```text
Network → Module 1: Packet Capture → Module 2: Packet Parsing → Module 3: Flow Builder → Feature Engineering
```

## Responsibility

Module 3 consumes `PacketMetadata` from Module 2 and groups packets that share
the same bidirectional 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`
into flows. Reverse-direction packets join the same flow via key canonicalization.

| Concern | Behavior |
|---------|----------|
| Idle timeout | Configurable `inactivity_timeout` closes quiet flows |
| Active timeout | Configurable `max_duration` prevents indefinitely long flows |
| Capacity | `max_active_flows` evicts the oldest flow when the cap is hit |
| Protocols | TCP / UDP with ports; ICMP / Other without ports |
| Bad input | `None`, wrong types, or packets lacking IPs are skipped |

Completed `Flow` values expose start/end time, duration, packet/byte counts,
forward/reverse counters, the canonical key, and the ordered packet list for
downstream Feature Engineering.

## Usage

```python
from packet_capture import PacketCaptureEngine
from flow_builder import FlowBuilder

builder = FlowBuilder(inactivity_timeout=60.0, max_duration=300.0)
engine = PacketCaptureEngine(interface="lo0")

def on_packet(meta):
    for flow in builder.add_packet(meta):
        print(flow.protocol, flow.packet_count, flow.byte_count, flow.duration)

engine.capture_metadata(on_packet)
# At shutdown: for flow in builder.flush(): ...
```

Offline / tests:

```python
from packet_parsing import parse_packet
from flow_builder import FlowBuilder
```

## Test / run

From the project root:

```bash
source macvenv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
