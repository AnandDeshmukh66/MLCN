# MLCN final mini-project report — validation record

Audit and document completion date: 21 October 2026. Institutional template academic year: 2025–26. Repository commit: `95407efc1f5d2b413abc36b24824481df97f7306`.

**Completed deliverable: 74 actual rendered pages**, comprising 12 preliminary pages (i–xii) and 62 continuously numbered main/report pages (1–62). The editable technical manuscript is complete for student/guide review. Administrative placeholders remain intentionally unfilled.

- [Editable Word report](MLCN_Final_Mini_Project_Report.docx)
- [Rendered PDF proof](MLCN_Final_Mini_Project_Report.pdf)
- Supporting source, figures, audit evidence and render checks: `reports/workspace/`.

## Institutional compliance

The complete 11-page institutional PDF was extracted and its visual pages inspected, including cover, approval, declaration, contents and publications samples. Its sample contents sequence governs the preliminary order where narrative instructions differ. The implementation guide was read and checked against current code.

| Requirement | Status and evidence |
|---|---|
| A4 portrait; single column | Pass. Both Word sections are approximately 21 × 29.7 cm (Word twip rounding only); all PDF pages are 595.30 × 841.89 points. |
| Binding margin 3.75 cm; other margins 2.5 cm | Pass. Section XML verified. Text bounds and embedded image bounds checked against the printable area. |
| Times New Roman, 12-point body; 1.5 spacing | Pass. Normal style is Times New Roman 12 pt, line spacing 1.5. Paragraph separation is explicitly set; headings use real Word styles. |
| Single spacing in specified material | Pass. Abstract, declaration, approval, references, captions and table titles use single-spaced styles. No separate quotations or footnotes are used. |
| Table/figure text at least 8 pt | Pass. Table text 8–12 pt; numbered table text 9–10 pt; captions 10–11 pt. Figure master lettering remains approximately 8 pt or larger at final scale. |
| Institutional title and certificate samples | Pass with required placeholders. Institutional wording, hierarchy, logo and four unsigned faculty positions retained; no approval asserted. Declaration uses the sample wording and six unsigned student positions. |
| Preliminary sequence | Pass. Title, approval, declaration, acknowledgement, contents, tables, figures, abbreviations, symbols, abstract, CO–PO matrix. Collaboration/certification page is not applicable without verified evidence. |
| Preliminary Roman and main Arabic footers | Pass. Center-aligned PAGE fields; every rendered footer checked. Chapter 1 restarts at Arabic 1; numbering continues through Appendix, References and Publications. |
| Abstract approximately 100–200 words | Pass. 165 words; single spaced. |
| Five narrative chapters plus institutional appendices/references | Pass. Chapters 1–5 form the required narrative. Chapter 6 contains Appendix I–VI. Chapter 7 contains References / Literature Cited. Publications are separate. |
| 40–100 rendered pages | Pass. 74 pages measured from the final PDF, not estimated from Word metadata. No blank pages or chapter-ending one-line spill pages remain. |
| Updateable TOC, List of Tables and List of Figures | Pass. Three live TOC fields retained in DOCX and refreshed with LibreOffice before final save/PDF export. Seven chapter entries and caption destinations checked. |
| Chapter-based figure/table numbers | Pass. 15 figure and 23 numbered table captions use SEQ fields by chapter; the separate publications table is Table P.1. In-text numbers are generated from one manifest. |
| Caption positions and first textual reference | Pass. Titles above tables, captions below figures. All 38 numbered objects have an earlier explicit manuscript reference. Caption page locations verified in the PDF. |
| Editable tables and pagination | Pass. 28 real Word tables: 23 numbered tables plus five preliminary tables/layouts. Header repetition and prevention of row splitting verified. Long tables may continue with repeated headers. |
| Original diagrams and valid data charts | Pass. Nine original architectural/methodological diagrams and six evidence-based charts; SVG masters and 300-DPI PNG embeds. Institutional logo alone is extracted from the supplied sample. |
| Academic language and abbreviations | Pass. Third-person narrative; abbreviations expanded and listed. The mandatory first-person declaration is an unsigned institutional template. |
| Numbered references in citation order | Pass. Fourteen verified entries; first-occurrence order [1]–[14] checked in rendered main text. Journal volume underlined where applicable. Repository evidence is attributed through artifact paths and hashes. |
| CO–PO matrix | Template supplied, mapping pending. Four provisional CO rows and 12 PO columns contain explicit pending markers; no actual mapping or scale invented. |
| Publications table | Pass. Institutional five-column format; explicitly records that no candidate publication is verified. |
| Physical submission requirements | Student/department handoff. Confirm guide corrections/signatures, soft binding and single-sided printing on white paper ≥70 GSM; library copy should be acid-free/neutral or ≥85 GSM as specified. |

## Final rendering and layout checks

The report was created with python-docx and rendered with local LibreOffice 26.8.1.1. A Basic automation macro refreshes document fields and all indexes before saving the DOCX and exporting the PDF. PyMuPDF independently checks the exported pages. All pages were inspected in contact sheets, with full-size checks of preliminary samples, chapter transitions, technical diagrams, dense tables, charts and bibliography.

The final checks verify seven chapter starts, every Roman/Arabic footer, all caption locations, citation order, three live index fields, 38 SEQ caption fields, image/text bounds, repeated table headers and non-splitting rows. No unresolved manuscript tokens, field errors or blank pages were found. See `workspace/qa_results.json`, `workspace/final_checks.json` and `workspace/rendered/`.

| Chapter | PDF page | Printed page |
|---|---:|---:|
| 1 | 13 | 1 |
| 2 | 18 | 6 |
| 3 | 25 | 13 |
| 4 | 46 | 34 |
| 5 | 60 | 48 |
| 6 | 64 | 52 |
| 7 | 72 | 60 |

Word may repaginate after placeholder edits, font substitutions or renderer changes. Refresh the complete TOC and both caption lists after edits, then re-export and check the page count before submission. Editing order or inserting new objects also requires regenerating/updating the literal in-text cross-references.

## Verified metrics and provenance

| Evidence | Source and verification |
|---|---|
| Offline population | `models/xgboost_test_predictions.csv`: 251,812 rows with saved labels, all 24 finite features and winning-class confidence. All hard-label metrics independently recomputed. |
| Model replay | `models/xgboost_ids_multiclass.json` and `models/xgboost_ids_features.json`: 521 rounds, best iteration 520, 24 ordered features, five ordered classes. XGBoost 2.1.4 replay has zero predicted-class disagreements. |
| Historical evaluation | `models/xgboost_evaluation_results.json`, classification report and confusion-matrix CSV. Reconstructed confusion counts agree exactly with the supplied matrix. |
| ROC/PR evidence | Full probabilities regenerated from the model and test features in `workspace/regenerated_probabilities.npz`; curve arrays in `workspace/curves.json`. Historical probabilities were not falsely inferred from a single confidence column. |
| Training record | `Untitled-1.ipynb`, especially cells 54–57, and model metadata. Earlier notebook states are inconsistent; a clean top-to-bottom retraining and split lineage are not certified. |
| Raw dataset inventory | Eight `MachineLearningCVE/*.csv` files counted: 2,830,743 rows. The profile artifact describes 2,518,112 selected rows, a different population. |
| Saved laboratory validation | `logs/launcher/validation_report.txt` and `validation_detections.jsonl`: 1,159 genuine records, no per-flow fallback. Consecutive profile-block reconciliation retained in `workspace/saved_live_reconciliation.json`. |
| Test execution | `workspace/test_run_unrestricted.txt`: 202 tests in 28.078 s, 196 passed, six failures, no errors. Initial restricted-sandbox socket errors were resolved by the authorized unrestricted rerun; the six failures persisted. |
| Source preservation | 133 substantive original files were hashed and checked again; changed files: []. Application source, model artifacts and original logs were not edited. |

| Metric | Verified value |
|---|---:|
| accuracy | 0.994237764682 |
| balanced_accuracy | 0.995567960448 |
| macro_precision | 0.899307235979 |
| macro_recall | 0.995567960448 |
| macro_f1 | 0.933584851454 |
| weighted_precision | 0.995734554887 |
| weighted_recall | 0.994237764682 |
| weighted_f1 | 0.994721961604 |
| cohen_kappa | 0.980858160456 |
| matthews_correlation_coefficient | 0.980998634865 |
| Historical macro OVR ROC-AUC | 0.999912287457 |
| Regenerated macro OVR ROC-AUC | 0.999912299684 |
| Historical log loss | 0.024482715250 |
| Regenerated log loss | 0.024470387604 |

Brute Force: 906 true positives, nine false negatives, 799 false positives; precision 0.531378299, recall 0.990163934 and F1 0.691603053. All 799 false positives come from BENIGN rows. The older guide’s 1,338 figure is the total BENIGN error count across all attack classes, not the Brute Force false-positive count.

The maximum absolute drift between regenerated and saved winning-class confidence is 0.000597418646. Runtime XGBoost 2.1.4 differs from recorded training metadata 3.4.1, while requirements constrain runtime below 3.0. Label equality therefore establishes replay consistency, not bitwise equality of all scores. The one recorded batch inference duration (3.160199 s, four threads) excludes loading and DMatrix construction and is not a live throughput benchmark.

Saved profile opening-flow matches are BENIGN 298/298, Brute Force 4/5, DDoS 188/190, DoS 23/24 and Port Scan 115/119. Blocks were reconstructed using saved profile totals; original ProfileWindow objects and raw capture files were unavailable. These are selected-profile laboratory matches, not independently labelled network-wide detection accuracy. No new Windows/Npcap capture was performed. Mixed-source `detections.jsonl` records are excluded from genuine validation metrics.

Current feature code uses microseconds for timing features and seconds for rates, so the historical seconds-versus-microseconds mismatch is repaired in this repository state. Remaining nonstandard feature semantics, notebook inconsistencies, class imbalance, potential concurrency/lifecycle issues and synthetic-display provenance are discussed explicitly in the report.

## Figure inventory

| Figure | Caption / subject | Printed page | Evidence |
|---|---|---:|---|
| Fig. 3.1 | Overall MLCN architecture. Solid blocks show audited components; the dashed Gemini block is proposed. This is an architectural diagram, not a measured network topology. | 14 | Architectural/methodological; proposed elements labelled |
| Fig. 3.2 | Five-module processing pipeline and typed handoffs. The pipeline orchestrator connects existing module APIs and retains the genuine combined result. | 15 | Architectural/methodological; proposed elements labelled |
| Fig. 3.3 | Packet-to-flow transformation, completion and classification eligibility. Discard and completion rules are architectural conditions, not experimental detection rates. | 17 | Architectural/methodological; proposed elements labelled |
| Fig. 3.4 | Bidirectional key construction and orientation. Canonical endpoint ordering and forward-direction anchoring serve different purposes. | 18 | Architectural/methodological; proposed elements labelled |
| Fig. 3.5 | Feature-engineering workflow under the current 24-feature contract. Timing features use microseconds; rates use seconds. | 20 | Architectural/methodological; proposed elements labelled |
| Fig. 3.6 | XGBoost loading and inference. Confidence is the maximum model probability and is not a calibrated probability of a real intrusion. | 23 | Architectural/methodological; proposed elements labelled |
| Fig. 3.7 | Recorded training/evaluation methodology and audit replay. Early notebook outputs are inconsistent; the saved test artifacts and regenerated inference are independently checked. | 24 | Architectural/methodological; proposed elements labelled |
| Fig. 3.8 | Generator/receiver interaction and evidence paths. Profile reference medians do not bypass capture or enter the detector as synthetic feature vectors. | 27 | Architectural/methodological; proposed elements labelled |
| Fig. 3.9 | Proposed Gemini explanation architecture. Dashed blocks are unimplemented design elements; only genuine evidence is eligible for explanation. | 31 | Architectural/methodological; proposed elements labelled |
| Fig. 4.1 | Verified class distribution in models/xgboost_test_predictions.csv, n = 251,812. Bar heights use a logarithmic count axis. | 35 | Verified saved or regenerated data; provenance in caption and Chapter 4 |
| Fig. 4.2 | Per-class precision, recall and F1 reconstructed from saved offline labels. Brute Force precision is substantially below the other classes. | 38 | Verified saved or regenerated data; provenance in caption and Chapter 4 |
| Fig. 4.3 | Verified offline confusion matrix. Cell annotations are exact counts; colour represents log10(count + 1). Rows are actual and columns predicted. | 39 | Verified saved or regenerated data; provenance in caption and Chapter 4 |
| Fig. 4.4 | One-versus-rest ROC curves regenerated from the saved booster and test features using XGBoost 2.1.4. These are offline ranking results. | 41 | Verified saved or regenerated data; provenance in caption and Chapter 4 |
| Fig. 4.5 | One-versus-rest PR curves from regenerated probabilities. The black point shows the separate Brute Force multiclass argmax operating point. | 41 | Verified saved or regenerated data; provenance in caption and Chapter 4 |
| Fig. 4.6 | Saved laboratory opening-flow counts, reconciled using consecutive JSONL blocks and the saved report’s profile totals. Matching is relative to the selected profile. | 45 | Verified saved or regenerated data; provenance in caption and Chapter 4 |

## Table inventory

| Table | Title | Printed page |
|---|---|---:|
| 1.1 | Investigation objectives and evidence boundaries | 4 |
| 2.1 | Critical literature comparison | 10 |
| 2.2 | Verified related patent publications | 12 |
| 3.1 | Core data contracts and interfaces | 15 |
| 3.2 | Feature families and current semantics | 20 |
| 3.3 | Recorded final notebook training configuration | 25 |
| 4.1 | Result provenance and permitted interpretation | 34 |
| 4.2 | Offline evaluation summary | 36 |
| 4.3 | Verified per-class offline evaluation | 37 |
| 4.4 | Exact confusion matrix (actual rows, predicted columns) | 39 |
| 4.5 | Regenerated one-versus-rest ranking metrics | 42 |
| 4.6 | Same-test-population baseline comparison | 42 |
| 4.7 | Saved laboratory validation, opening-flow denominator | 44 |
| 4.8 | Failures in the 202-test audit run | 46 |
| 5.1 | Objective achievement and remaining work | 48 |
| 6.1 | Complete ordered 24-feature runtime contract | 52 |
| 6.2 | Audited implementation and artifact inventory | 54 |
| 6.3 | Configuration by execution context | 55 |
| 6.4 | Reproducibility and laboratory command reference | 56 |
| 6.5 | Proposed Gemini evidence and response contract | 57 |
| 6.6 | Local CIC CSV row counts | 58 |
| 6.7 | Selected artifact SHA-256 hashes | 59 |
| P.1 | Candidate publications status | 62 |

Additional preliminary tables are the approval signature layout, declaration signature layout, abbreviations, symbols and pending CO–PO matrix. They are intentionally unnumbered.

## Citation and patent verification

Online verification used original papers, author/institution-hosted pages, dataset providers, official Gemini documentation and Google Patents publication records. Fourteen sources are cited; no DOI or patent identifier was invented. Where publisher access was unavailable, the report uses verified arXiv, university-hosted or dataset-provider records and omits unverified bibliographic fields.

| Citation | Verified source | Verification scope |
|---|---|---|
| [1] | [Sommer R., Paxson V., “Outside the Closed World: On Using Machine Learning for Network Intrusion Detection,” 2010 IEEE Symposium on Security and Privacy (2010).](https://gangw.cs.illinois.edu/class/cs562/papers/Closed_World-IDS-sp10.pdf) | Original paper hosted by a university; authors, title, venue and argument checked. |
| [2] | [Canadian Institute for Cybersecurity, University of New Brunswick, “Intrusion Detection Evaluation Dataset (CIC-IDS2017).” Dataset documentation, including the cited study by Sharafaldin I., Lashkari A. H. and Ghorbani A. A., “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” 4th International Conference on Information Systems Security and Privacy (2018).](https://www.unb.ca/cic/datasets/ids-2017.html) | Official UNB dataset page and associated-paper metadata; five-day collection checked. |
| [3] | [Chen T., Guestrin C., “XGBoost: A Scalable Tree Boosting System,” arXiv:1603.02754 (2016), associated conference DOI: 10.1145/2939672.2939785.](https://arxiv.org/abs/1603.02754) | Original arXiv record and linked conference DOI. |
| [4] | [Handley M., Paxson V., Kreibich C., “Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics,” 10th USENIX Security Symposium, Washington, D.C. (2001).](https://www.usenix.org/conference/10th-usenix-security-symposium/network-intrusion-detection-evasion-traffic-normalization) | USENIX paper/venue record. |
| [5] | [Canadian Institute for Cybersecurity, University of New Brunswick, “DDoS Evaluation Dataset (CIC-DDoS2019).” Dataset documentation and associated study by Sharafaldin I., Lashkari A. H., Hakak S. and Ghorbani A. A., “Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy,” IEEE 53rd International Carnahan Conference on Security Technology, Chennai (2019).](https://www.unb.ca/cic/datasets/ddos-2019.html) | Official UNB dataset page and associated-paper metadata. |
| [6] | [Stratosphere Laboratory, “The CTU-13 Dataset: A Labeled Dataset with Botnet, Normal and Background Traffic.” Dataset-provider documentation, accessed 21 October 2026.](https://www.stratosphereips.org/datasets-ctu13) | Dataset-provider description; comparison only, not MLCN training input. |
| [7] | [Engelen G., Rimmer V., Joosen W., “Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study,” 2021 IEEE Security and Privacy Workshops, pp. 7–12 (2021), DOI: 10.1109/SPW53761.2021.00009.](https://intrusion-detection.distrinet-research.be/WTMC2021/index.html) | Author research-group publication page, paper metadata and DOI. |
| [8] | [Arp D., Quiring E., Pendlebury F., Warnecke A., Pierazzi F., Wressnegger C., Cavallaro L., Rieck K., “Dos and Don’ts of Machine Learning in Computer Security,” 31st USENIX Security Symposium, pp. 3971–3988 (2022).](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) | Official USENIX publication page and paper metadata. |
| [9] | [Saito T., Rehmsmeier M., “The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets,” PLOS ONE, vol. 10, no. 3, e0118432 (2015), DOI: 10.1371/journal.pone.0118432.](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0118432) | Original PLOS article, DOI and journal metadata. |
| [10] | [Lundberg S., Lee S.-I., “A Unified Approach to Interpreting Model Predictions,” arXiv:1705.07874 (2017).](https://arxiv.org/abs/1705.07874) | Original arXiv record; attribution-method discussion. |
| [11] | [Ribeiro M. T., Singh S., Guestrin C., “Why Should I Trust You?: Explaining the Predictions of Any Classifier,” arXiv:1602.04938 (2016).](https://arxiv.org/abs/1602.04938) | Original arXiv record; local-surrogate discussion. |
| [12] | [Google, “Structured Outputs,” Gemini API documentation. Accessed 21 October 2026; page update shown as 20 October 2026.](https://ai.google.dev/gemini-api/docs/structured-output) | Official structured-output documentation; accessed 21 October 2026. Proposed design only; no API call or implementation claim. |
| [13] | [Powell M. S., Drozdenko B. M., Roodbeen S. A., “Real-time Network Intrusion Detection System,” US12143406B1, published 12 November 2024; original assignee: United States Department of the Navy.](https://patents.google.com/patent/US12143406B1/en) | Publication ID, inventors, title, priority/publication dates and relevant technical description checked. |
| [14] | [Papamartzivanos D., Bifulco R., Kambourakis G., Gomez Marmol F., “Method and System for Adaptive Network Intrusion Detection,” US20220021695A1, published 20 January 2022; original assignee: NEC Laboratories Europe GmbH.](https://patents.google.com/patent/US20220021695A1/en) | Publication ID, inventors, title, priority/publication dates and relevant technical description checked. |

Patent search terms combined “network intrusion detection”, “machine learning”, “flow features”, “real-time classification” and “adaptive representation”. Verified records: US12143406B1 (published 12 November 2024, priority 1 September 2022) and US20220021695A1 (published 20 January 2022, priority 9 November 2018). This is a limited technical related-work review, not an exhaustive patent landscape, novelty determination or freedom-to-operate opinion. No candidate publication is asserted.

## Required student and guide inputs

- Student names, roll numbers and actual number of candidates; remove unused declaration positions.
- Branch and department; guide, co-guide if applicable, coordinator and head of department names.
- Actual signatures and approval after authorized review; the supplied templates are unsigned.
- Acknowledgements based on actual assistance, funding and any required disclosure of document-generation support.
- Department-approved CO/PO definitions, row/column count, mappings, correlation rubric, evaluator and approval date.
- Confirm submission date and academic year: 2025–26 is retained from the supplied institutional template, while repository inspection occurred in October 2026.
- Supply collaboration certificates or genuine publication records only if applicable; none were verified.

## Limitations and completion boundary

The document-generation workflow is complete: editable DOCX, compatible rendered proof, original figures, verified evidence and validation record are supplied. Formal institutional approval cannot be completed without the student/faculty inputs above. Six existing repository tests fail in synthetic-result labelling/presentation; these failures are documented rather than repaired because application-source changes were prohibited.

Offline model replay does not certify clean retraining, independent test provenance, live capture performance or deployment generalization. The saved notebook has inconsistent earlier outputs, and possible preprocessing-before-split leakage is discussed. Laboratory logs have narrower provenance than an independently labelled capture dataset. Gemini XAI and optional SHAP integration remain proposed and unmeasured.

Final rendering was verified with LibreOffice, not Microsoft Word itself. The DOCX retains editable paragraphs/tables, styles, fields and images; SVG figure masters are available separately. Placeholder edits may change pagination. Physical printing, binding, signatures, university acceptance and any publication status remain outside digital validation.

## Reproduction and artifact integrity

Report-only scripts are retained: `audit.py`, `check_saved_live.py`, `make_figures.py`, `report_data.py`, `manuscript.md`, `generate_report.py`, `install_render_macro.py`, `render_macro.bas`, `qa_report.py`, `final_checks.py` and `write_validation.py`. The local renderer, profile and Python environment are confined to the report workspace. Run audit regeneration only when intentionally updating evidence; it may produce a different single-run timing.

For document-only regeneration from the repository root, run `PYTHONDONTWRITEBYTECODE=1 reports/workspace/venv/bin/python reports/workspace/generate_report.py`, then the local LibreOffice `macro:///Standard.Module1.RenderReport` with `lo_profile`. Run `qa_report.py`, `final_checks.py` and `write_validation.py` with the same report Python. Regeneration overwrites the report, so preserve any later manual student edits before running it.

- Final DOCX SHA-256: `66025ec83da614c8f05008f13fa7ac9238270f415ecc9bac57f93ea98629d15a`
- Final PDF SHA-256: `e434e82e47337918f0df2de6146ec47d70ac5950e492f19e8268d97960fdfa16`
- Original file hashes: `workspace/repository_inventory.json`
- Final original-file integrity result: `workspace/source_integrity_check.json`
