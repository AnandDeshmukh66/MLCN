# MLCN Common Feature Schema Report

Schema version: **1.0.0**

## Summary

- Candidate features evaluated: **25**
- Features retained: **24**
- Features removed: **1**
- Validation status: **PASSED**

## Retained features (fixed order)

1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Fwd Packets Length Total
5. Bwd Packets Length Total
6. Fwd Packet Length Mean
7. Bwd Packet Length Mean
8. Flow Bytes/s
9. Flow Packets/s
10. Flow IAT Mean
11. Flow IAT Std
12. Fwd IAT Mean
13. Bwd IAT Mean
14. Packet Length Mean
15. Packet Length Std
16. FIN Flag Count
17. SYN Flag Count
18. RST Flag Count
19. PSH Flag Count
20. ACK Flag Count
21. URG Flag Count
22. Down/Up Ratio
23. Active Mean
24. Idle Mean

## Removed / rejected candidates

- **Average Packet Size** (candidate #22): Algebraically equivalent to Packet Length Mean when Module 3 maintains byte_count == sum(PacketMetadata.length). Retain Packet Length Mean only to avoid duplicate schema columns.

## Validation

- No validation errors.

## Module compatibility

All retained features are derivable from `PacketMetadata` and `Flow` without changing Module 3. Activity/idle statistics use a fixed 5.0s threshold aligned with CICFlowMeter defaults, but omit synthetic trailing idle padding at flow close.

## Artifacts

- Machine-readable schema: `data/common_feature_schema.json`
- This report: `data/common_feature_schema_report.md`
