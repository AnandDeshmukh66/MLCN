# MLCN — End-to-End Pipeline Integration (Modules 1–5)

Connects the existing modules through their public interfaces. Module internals
are not rewritten.

```text
Network traffic
  → Module 1 PacketCaptureEngine.capture_metadata / parse_packet
  → Module 2 PacketMetadata
  → Module 3 FlowBuilder.add_packet / flush → Flow
  → Module 4 FeatureEngineeringEngine.extract → FeatureVector (24)
  → Module 5 MLDetectionEngine.predict → DetectionResult
  → PipelineResult
```

## Run (live)

Windows (Administrator + Npcap):

```bat
cd D:\MLCN
.\venv\Scripts\activate
pip install -r requirements.txt
python -m pipeline -i "Ethernet"
python -m pipeline -l
```

macOS / Linux (elevated privileges):

```bash
source macvenv/bin/activate
sudo python -m pipeline -i lo0
```

## Run (offline / tests)

```python
from pipeline import IntrusionDetectionPipeline

pipeline = IntrusionDetectionPipeline()
results = pipeline.process_raw_packets(raw_scapy_packets, flush=True)
for result in results:
    print(result.predicted_class, result.confidence)
```

```bash
python -m unittest discover -s tests -v
```

## Model artifacts

Module 5 loads the trained JSON booster from `models/` or, if present, `xgboost/`
(Windows layouts). Prefer `models/` so the folder does not shadow `import xgboost`.

## Notes

- Ctrl+C stops live capture; active flows are flushed before exit.
- Invalid / non-IP packets are skipped without stopping the pipeline.
- Live sniffing needs privileges (Windows: Npcap + Admin; macOS/Linux: sudo).
