# MLCN Common Feature Schema Report

Schema version: **2.0.0**

## Summary

- Candidate features evaluated: **25**
- Features retained: **24**
- Features removed: **1**
- Validation status: **PASSED**

## Retained features (fixed model order)

1. Flow Duration (microseconds)
2. Total Fwd Packets (packets)
3. Total Backward Packets (packets)
4. Fwd Packets Length Total (payload bytes)
5. Bwd Packets Length Total (payload bytes)
6. Fwd Packet Length Mean (payload bytes)
7. Bwd Packet Length Mean (payload bytes)
8. Flow Bytes/s (payload bytes per second)
9. Flow Packets/s (packets per second)
10. Flow IAT Mean (microseconds)
11. Flow IAT Std (microseconds)
12. Fwd IAT Mean (microseconds)
13. Bwd IAT Mean (microseconds)
14. Packet Length Mean (payload bytes)
15. Packet Length Std (payload bytes)
16. FIN Flag Count (binary)
17. SYN Flag Count (binary)
18. RST Flag Count (binary)
19. PSH Flag Count (binary)
20. ACK Flag Count (binary)
21. URG Flag Count (binary)
22. Down/Up Ratio (ratio)
23. Active Mean (microseconds)
24. Idle Mean (microseconds)

## Removed / rejected candidates

- **Average Packet Size** (candidate #22): Near-duplicate of Packet Length Mean (same payload sum; n instead of n + 1 values). The trained model uses only Packet Length Mean.

## Validation

- No validation errors.

## CIC-IDS2017 semantics

- Time features are microseconds; Flow Bytes/s and Flow Packets/s are per second.
- Lengths are transport payload bytes, including Ethernet padding.
- Packet Length Mean/Std use n + 1 values (first payload counted twice).
- Flag columns are binary bits of the first packet in CICFlowMeter's permuted columns.
- Down/Up Ratio is floor(backward / forward).
- Active/Idle use a 5 s threshold; the trailing active span is not recorded and the closing FIN does not update activity.
- Flows end on the first FIN or after 120 s; flows with fewer than 2 packets or other than TCP/UDP are not classified.

Units and types come from `feature_engineering/contract.py`.

## Artifacts

- Machine-readable schema: `data/common_feature_schema.json`
- This report: `data/common_feature_schema_report.md`
