# MLCN Implementation Guide

## 1. Big picture

MLCN is a small, lab-only network intrusion-detection demonstration. It creates controlled HTTP/TCP traffic patterns, captures packets on a receiver, converts each network conversation into numbers, and asks a saved XGBoost model whether that conversation looks **BENIGN**, **Brute Force**, **DDoS**, **DoS**, or **Port Scan**.

The implemented system ends at classification. The root README describes future/aspirational components such as SHAP, LLM threat reports, an incident database, and a SOC dashboard, but they are not implemented in this repository (`README.md`).

```text
Optional Streamlit traffic generator
  → safe socket/HTTP traffic → receiver/Npcap capture
  → Scapy packet parsing → bidirectional flow assembly
  → 24-feature vector → saved XGBoost booster
  → terminal prediction, or Streamlit validation table
```

The model classifies **completed flows**, not individual packets. A flow is a bidirectional IP/port/protocol conversation that is closed after inactivity, maximum age, capacity eviction, or shutdown (`flow_builder/builder.py`).

## 2. Startup and actual runtime flow

The supplied Windows command is the placeholder `<PASTE MY WINDOWS COMMAND HERE>`, so its exact flags and entry point are **not verifiable from the repository**. The documented receiver command is:

```bat
python -m pipeline -i "Ethernet"
```

For the intended two-machine Windows lab, the documented form is:

```bat
python -m pipeline -i "Wi-Fi,\Device\NPF_Loopback" --lab-port 8080
```

Run this in an Administrator PowerShell after installing Npcap; use `python -m pipeline -l` to obtain the exact adapter names (`pipeline/README.md`, `traffic_generator/README.md`).

| Step | What happens | Code and data in | Output / next destination |
|---|---|---|---|
| 1. CLI starts | `python -m pipeline` parses interface, timeouts, optional lab port, and verbosity. | `pipeline/__main__.py` → `pipeline/cli.py`; CLI arguments | Creates `IntrusionDetectionPipeline`. `--lab-port 8080` also creates BPF filter `tcp port 8080`. |
| 2. Pipeline initializes | It builds one flow builder, one 24-feature extractor, and one model detector. The detector loads artifacts before traffic is captured. | `pipeline/engine.py` | Ready to accept packet metadata. Initialization fails clearly if model files/schema do not match. |
| 3. Npcap/Scapy captures | `PacketCaptureEngine` resolves one or comma-separated interfaces and calls Scapy `sniff(..., store=False)` in one worker per interface. | `packet_capture/capture.py`, `packet_capture/interfaces.py`; raw Scapy packets | Each valid packet is sent to Module 2. Npcap is the Windows driver that lets Scapy access adapters; Administrator rights are required. |
| 4. Packet parsing | IPv4/IPv6 addresses, TCP/UDP ports, protocol, observed packet length, timestamp, TCP flags, TTL/hop limit, and TCP window are normalized. Bad packets return `None` instead of stopping capture. | `packet_parsing/parser.py`; raw Scapy `Packet` | `PacketMetadata` goes to the pipeline. Non-IP frames cannot form a flow and are skipped later. |
| 5. Flow building | Packets with the same canonical bidirectional 5-tuple are accumulated. “Forward” means the direction of the **first observed packet**, not necessarily client-to-server. | `flow_builder/builder.py`; `PacketMetadata` | A completed `Flow`, then Module 4. Defaults: 60 s idle timeout, 300 s max duration, 100,000 active flows (`pipeline/cli.py`). |
| 6. Feature extraction | The completed flow becomes exactly 24 ordered numeric features: counts, byte sizes, rates, timing statistics, TCP flag counts, and active/idle means. | `feature_engineering/engine.py`, `feature_engineering/schema.py`; `Flow` | `FeatureVector(values=...)` in the fixed schema order. |
| 7. Inference | Values are checked for count (24), numeric type, finite values, and exact feature order. They are made into an XGBoost `DMatrix`; the largest of five probabilities is selected. | `ml_detection/engine.py`; `FeatureVector` | `DetectionResult`: class ID/name, confidence, and all class probabilities. |
| 8. Display | The pipeline CLI prints one line per completed flow: prediction, confidence, protocol/endpoints, packet/byte count, duration. Ctrl+C closes remaining flows and runs them through M4→M5. | `pipeline/cli.py`, `pipeline/engine.py` | Terminal output and in-memory `PipelineResult` list. There is no receiver-side persistent detection log/database. |

### Model location and loading

The actual trained model is the JSON XGBoost booster:

```text
models/xgboost_ids_multiclass.json
models/xgboost_ids_features.json   # feature names, classes, best iteration
```

`ml_detection/schema.py` prefers `models/`, with a fallback to an `xgboost/` directory for an older Windows layout. `MLDetectionEngine` loads the booster with `xgboost.Booster.load_model()`, validates its feature names against the common schema, and uses the saved best iteration, **520** (`ml_detection/engine.py`, `models/xgboost_ids_features.json`). No scaler, encoder, or other preprocessing artifact is loaded.

## 3. ML pipeline

### Data and labels

The repository contains saved model/evaluation artifacts and compact empirical profiles, but **does not contain the raw training dataset or training script**. The feature schema says it normalizes CICIDS2017, CIC-DDoS2019, and CTU-13-style data (`data/common_feature_schema.json`), while the traffic-profile file calls its source “CICIDS-based.” The exact source files, label mapping process, split method, and training procedure are therefore **not verifiable from the repository**.

The five predicted labels are:

```text
BENIGN | Brute Force | DDoS | DoS | Port Scan
```

The profile artifact records 2,518,112 source samples: BENIGN 2,096,377 (83.3%), DoS 193,748 (7.7%), DDoS 128,016 (5.1%), Port Scan 90,819 (3.6%), and Brute Force 9,152 (0.36%) (`assets/MLCN_compact_attack_traffic_profiles.json`). The saved test report contains 251,812 rows and has a very similar distribution, so it appears to be an approximately 10% held-out subset; that interpretation is based on counts, not an explicit split record (`models/xgboost_evaluation_results.json`).

### Input features, in plain language

The fixed order is stored in `data/common_feature_schema.json` and duplicated/validated by `models/xgboost_ids_features.json`.

| Feature group | Features | Meaning |
|---|---|---|
| Conversation size | Flow Duration; Total Fwd/Backward Packets; Fwd/Bwd Packets Length Total | How long the exchange lasted, how much each direction spoke, and how much data it carried. |
| Typical packet/rate | Fwd/Bwd Packet Length Mean; Packet Length Mean/Std; Flow Bytes/s; Flow Packets/s | Packet-size shape and how quickly traffic arrived. |
| Timing | Flow/Fwd/Bwd IAT Mean; Flow IAT Std; Active Mean; Idle Mean | Gaps between packets, variability, and bursts separated by gaps over 5 seconds. |
| TCP behavior | FIN, SYN, RST, PSH, ACK, URG Flag Count | Connection setup, acknowledgement, data push, reset, and termination behavior. Non-TCP traffic normally contributes zero flags. |
| Direction balance | Down/Up Ratio | In this implementation, forward packet count divided by reverse packet count, or zero if either side has no packets. |

Why these were selected is partly documented: 25 candidates were evaluated and **Average Packet Size** was removed because it is algebraically equivalent to Packet Length Mean, so retaining both would duplicate information (`data/common_feature_schema_report.md`). The profile file also ranks discriminative features per attack, for example DDoS Flow IAT Std, DoS Fwd IAT Mean, Port Scan Fwd Packets Length Total, and Brute Force Total Backward Packets (`assets/MLCN_compact_attack_traffic_profiles.json`). Any broader claim about feature-selection method is **not verifiable from the repository**.

### Preprocessing, model, and evaluation

- **Live transformations:** parse → aggregate → calculate 24 values. Values are converted to floats, but there is no scaling, normalization, one-hot encoding, imputation, or learned preprocessing in the inference code (`feature_engineering/engine.py`, `ml_detection/engine.py`).
- **Model:** an inference-only five-class XGBoost `Booster`. Important recorded settings are 24 inputs, five classes, XGBoost version 3.4.1, best iteration 520, and best validation multiclass log loss 0.02571 (`models/xgboost_ids_features.json`, `models/xgboost_evaluation_results.json`). Hyperparameters such as tree depth, learning rate, objective, and class weighting are **not verifiable from repository-readable metadata**.
- **Saved test metrics:** accuracy 99.42%, balanced accuracy 99.56%, macro F1 93.36%, weighted F1 99.47%; ROC-AUC macro 0.99991 (`models/xgboost_evaluation_results.json`).

| Class | Test support | Precision | Recall | F1 | Reading |
|---|---:|---:|---:|---:|---|
| BENIGN | 209,638 | 99.95% | 99.36% | 99.65% | Strong offline result |
| Brute Force | 915 | 53.14% | 99.02% | 69.16% | Finds most labeled Brute Force rows, but many predicted rows are actually something else |
| DDoS | 12,802 | 99.64% | 99.97% | 99.81% | Strong offline result |
| DoS | 19,375 | 97.96% | 99.53% | 98.74% | Strong offline result |
| Port Scan | 9,082 | 98.96% | 99.91% | 99.44% | Strong offline result |

These are offline-artifact numbers, not proof of live Npcap performance.

## 4. Model and data problems

### Confirmed issues

1. **Critical — live feature time units do not match the saved evaluation feature units.** The live engine explicitly computes duration/IAT/active/idle values in **seconds** (`feature_engineering/engine.py`; `data/common_feature_schema.json`). Saved evaluation rows use values such as `Flow Duration=5776979` and `Flow IAT Mean=1925659.67`; the traffic generator explicitly treats profile timing values as **microseconds** (`models/xgboost_test_predictions.csv`, `traffic_generator/config.py`). The pipeline sends live seconds straight to the model with no conversion (`pipeline/engine.py`). This can move live traffic far outside the model’s training feature space, so the excellent saved test metrics cannot be assumed to apply live.

2. **High — Brute Force has poor precision and extremely little representation.** Only 915 Brute Force test rows exist; precision is 53.14%, compared with 97.96–99.95% for other classes. The confusion matrix shows 799 BENIGN, 46 DDoS, 398 DoS, and 95 Port Scan rows predicted as Brute Force—1,338 false positives versus 906 true positives (`models/xgboost_confusion_matrix.csv`). This makes the class noisy in an alerting setting.

3. **High — traffic-generator “attack” labels are target profiles, not established receiver detections.** The UI calls the selected profile `target_profile` and displays a match only when model output equals that profile (`traffic_generator/validation.py`). It produces bounded ordinary TCP/HTTP activity: Brute Force sends no credentials, DDoS is up to ten concurrent slow connections, and Port Scan uses normal TCP `connect()` probes (`traffic_generator/traffic_generator.py`, `traffic_generator/config.py`). That is safe and appropriate for a lab, but it does not prove feature equivalence to the data used to train the model.

4. **Medium — real-time output is delayed until a flow closes.** Default idle timeout is 60 seconds and busy flows can remain active for five minutes (`pipeline/cli.py`, `flow_builder/builder.py`). A flow may therefore have no classification while traffic is still active. Shutdown flushes flows, but that is not continuous detection.

### Risks (technically plausible, not proven)

- **Feature-direction mismatch:** CIC-style datasets often define forward as initiator/client direction, while this code defines it as the first packet captured. Capture can start mid-flow or miss the initial packet, changing forward/backward features (`flow_builder/builder.py`, `data/common_feature_schema.json`). Training direction convention is not supplied.
- **Flow-boundary mismatch:** live flows use configurable 60-second idle / 300-second active timeouts, while the training flow generator and its timeouts are not supplied. The 5-second active/idle split alone does not establish equivalent flow segmentation.
- **Multi-interface duplicate/partial capture:** Wi-Fi and loopback are captured concurrently (`packet_capture/capture.py`). There is no packet deduplication or cross-interface ordering mechanism. The repository does not show that one flow will be captured twice, but it can produce incomplete or distorted flow statistics if visibility differs by adapter.
- **Offline evaluation leakage/overfitting cannot be assessed:** no training code, split grouping strategy, source-day separation, or preprocessing pipeline is present. A random row split of related flows would overstate generalization, but that is not proven here.

### Unknown

- Exact raw datasets, cleaning, label consolidation, sampling, split/validation method, and XGBoost training hyperparameters.
- Whether a Windows/Npcap run has successfully classified each generator profile end to end. The included generator logs record sent connections/bytes, not model predictions (`logs/traffic_generator/`).
- Live capture packet loss, Npcap driver/version behavior, and whether the selected Windows adapter sees the intended traffic. The code advises using both Wi-Fi and `\Device\NPF_Loopback`, but repository logs do not measure capture quality.

## 5. Current implementation: how modules fit

```text
Capture                    Parse                    Flow
PacketCaptureEngine   →    parse_packet        →    FlowBuilder
Scapy/Npcap packets         PacketMetadata            completed Flow

Features                   Model                    Detection/UI
FeatureEngineeringEngine → MLDetectionEngine     →  CLI output / optional Streamlit validation
24-value FeatureVector      XGBoost probabilities     PipelineResult
```

The receiver path is genuinely connected end-to-end in `pipeline/engine.py`; integration tests exercise handoffs and a mocked live capture path (`tests/test_pipeline_e2e.py`). The model tests load the real saved booster and verify one saved representative vector for each class (`tests/test_ml_detection.py`).

### What Streamlit displays

Streamlit is **not a live SOC dashboard**. `traffic_generator/streamlit_app.py` is a controlled traffic-generator UI. It displays:

- selected profile and eight reference medians from `assets/MLCN_compact_attack_traffic_profiles.json`;
- safety confirmation, progress/status, generator logs, and run statistics;
- optional single-machine validation results: selected target profile, observed flow size/duration, model prediction, confidence, and match rate.

The reference medians are explicitly **not injected into model features** (`traffic_generator/profile_loader.py`). In validation mode, `LocalValidationRunner` starts a loopback echo server and the real M1→M5 pipeline, then renders actual in-memory pipeline results (`traffic_generator/controller.py`, `traffic_generator/validation.py`). In two-machine mode, no predictions return to Streamlit; they print on the receiver terminal. The UI’s labels/logs/progress are generator-side state, not receiver detections.

## 6. What is going wrong?

| Problem | Evidence | Why it matters | Recommended fix | Priority |
|---|---|---|---|---|
| Train/live time-unit mismatch | Live code uses seconds; saved evaluation/profile values are microsecond-scale | Model thresholds are applied to values up to 1,000,000× smaller live | Choose one canonical unit, regenerate/retrain or convert **all** time features before inference, then validate against a held-out live-captured dataset. Update `feature_engineering/engine.py`, schema, model artifacts/training pipeline. | Critical |
| Brute Force false positives | 53.14% precision; 1,338 false positives in saved confusion matrix | More than half of Brute Force alerts may be wrong offline | Rebuild a labeled evaluation set; add representative Brute Force data, inspect error features, tune/retrain, and report PR curves. Training pipeline/dataset is absent and must be added. | High |
| Generated traffic is not validated as model-equivalent | Generator maps profile medians into safe sockets/HTTP, then labels selected profile as target | Selecting “DDoS” does not establish that the detector should say DDoS | Capture runs, save observed 24 features plus predictions, compare distributions to training data, and only claim validated profiles after measured acceptance criteria. `traffic_generator/validation.py`, `traffic_generator/traffic_generator.py`. | High |
| Classification arrives only when flows close | 60 s idle and 300 s max defaults | Alerts may be late during an ongoing event | Select/test task-appropriate expiration and/or implement safe periodic flow snapshots; keep feature definitions consistent with retraining. `pipeline/cli.py`, `flow_builder/builder.py`. | Medium |
| Receiver has no durable detection output | Results stay in memory / print to terminal; traffic logs only describe generator runs | Alerts disappear at process exit and Streamlit cannot show remote receiver findings | Add an explicit detection sink with structured records, then have a UI consume it. `pipeline/engine.py`, new reporting/storage module. | Medium |

## 7. Final mental model

### What happens when I run this project?

1. You start the **receiver** with `python -m pipeline` on a Windows adapter visible to Npcap.
2. Npcap gives Scapy copies of packets seen on that adapter. For a local Windows lab, the useful path may be the Npcap loopback adapter; for a two-machine lab, it may require both Wi-Fi and loopback.
3. Each captured IP packet is reduced to metadata. Packets in the same two-way conversation are collected into a flow.
4. When that conversation is idle, old enough, evicted, or the program stops, MLCN calculates 24 numbers describing its timing, size, directions, and TCP flags.
5. The loaded JSON XGBoost model receives those values in a strict fixed order and returns five probabilities. The largest becomes the class and confidence printed by the pipeline.
6. If you run the **Streamlit generator**, it creates only safe lab traffic. In local validation mode it also starts the real receiver pipeline and shows its completed-flow predictions. With two machines, predictions remain on the receiver terminal.

### What should I fix next?

1. Resolve and test the seconds-versus-microseconds mismatch before trusting any live result.
2. Create a reproducible training/evaluation pipeline with raw-data provenance, flow construction rules, group-aware splits, preprocessing artifacts, and saved hyperparameters.
3. Capture labeled Windows/Npcap lab sessions and compare their 24-feature distributions and predictions with held-out training/evaluation data.
4. Improve Brute Force data and threshold/model behavior using false-positive analysis.
5. Add persistent structured detection records, then connect a receiver-side UI/dashboard to those records.
