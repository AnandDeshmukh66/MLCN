# MLCN — Module 4: Feature Engineering Engine

Converts completed Module 3 flows into the 24-feature numerical vector defined
by the common feature schema.

```text
Network → Module 1: Packet Capture → Module 2: Packet Parsing → Module 3: Flow Builder → Module 4: Feature Engineering → Module 5: ML Detection
```

## Responsibility

Module 4 consumes `Flow` objects from Module 3 and emits a deterministic,
ML-ready `FeatureVector` whose values follow the exact order, units and
formulas in `feature_engineering/contract.py` (documented in
`data/common_feature_schema.json`).

| Concern | Behavior |
|---------|----------|
| Feature count / order | Fixed 24 features matching `feature_engineering/contract.py` / XGBoost input |
| Units | Durations, IATs, Active/Idle in **microseconds**; Bytes/s and Packets/s per second |
| Lengths | Transport payload bytes (Ethernet padding included); Packet Length Mean/Std over n + 1 values |
| Direction | Forward = first packet orientation; backward = opposite; Down/Up = floor(bwd / fwd) |
| Rates | Zero-duration flows use the training-set medians (`ZERO_DURATION_RATE_FILL`) |
| IAT / length std | Sample standard deviation (`ddof=1`); `0.0` with < 2 samples |
| TCP flags | Binary bits of the **first** packet in CICFlowMeter's permuted columns; non-TCP → 0 |
| Active / Idle | Recorded only at gaps > 5 s; no trailing active span; closing FIN ignored |
| Bad input | Non-`Flow` raises `TypeError`; empty flows yield zeros where defined |

## Usage

```python
from packet_capture import PacketCaptureEngine
from flow_builder import FlowBuilder
from feature_engineering import FeatureEngineeringEngine
from ml_detection import MLDetectionEngine

builder = FlowBuilder(inactivity_timeout=60.0, max_duration=300.0)
engine = PacketCaptureEngine(interface="lo0")
fe = FeatureEngineeringEngine()
detector = MLDetectionEngine()

def on_packet(meta):
    for flow in builder.add_packet(meta):
        result = detector.predict(fe.extract(flow))
        print(result.predicted_class, result.confidence)

engine.capture_metadata(on_packet)
# At shutdown: for flow in builder.flush(): detector.predict(fe.extract(flow))
```

Offline / tests:

```python
from feature_engineering import extract_features, FEATURE_ORDER

vector = extract_features(flow)
assert len(vector) == 24
assert list(vector.names) == list(FEATURE_ORDER)
```

## Test / run

From the project root:

```bash
source macvenv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
