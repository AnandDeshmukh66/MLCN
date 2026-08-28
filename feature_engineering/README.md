# MLCN — Module 4: Feature Engineering Engine

Converts completed Module 3 flows into the 24-feature numerical vector defined
by the common feature schema.

```text
Network → Module 1: Packet Capture → Module 2: Packet Parsing → Module 3: Flow Builder → Module 4: Feature Engineering → Module 5: ML Detection
```

## Responsibility

Module 4 consumes `Flow` objects from Module 3 and emits a deterministic,
ML-ready `FeatureVector` whose values follow the exact order and formulas in
`data/common_feature_schema.json`.

| Concern | Behavior |
|---------|----------|
| Feature count / order | Fixed 24 features matching the schema / XGBoost input |
| Direction | Forward = first packet orientation; backward = opposite |
| Rates | Bytes/s and packets/s are `0.0` when duration is 0 |
| IAT / length std | Sample standard deviation (`ddof=1`); `0.0` with < 2 samples |
| TCP flags | Counts `F/S/R/P/A/U` in `PacketMetadata.tcp_flags`; non-TCP → 0 |
| Active / Idle | Gaps vs 5.0s threshold; no synthetic idle padding at flow close |
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
