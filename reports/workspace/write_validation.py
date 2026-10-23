from pathlib import Path
import json
W=Path(__file__).parent;R=W.parent
A=json.loads((W/'audit_results.json').read_text());M=json.loads((W/'document_manifest.json').read_text());F=json.loads((W/'final_checks.json').read_text());Q=json.loads((W/'qa_results.json').read_text());I=json.loads((W/'source_integrity_check.json').read_text());E=json.loads((R.parent/'models/xgboost_evaluation_results.json').read_text())
out=[]
def p(s=''):out.append(s)
p('# MLCN final mini-project report — validation record\n')
p('Audit and document completion date: 21 October 2026. Institutional template academic year: 2025–26. Repository commit: `95407efc1f5d2b413abc36b24824481df97f7306`.\n')
p(f'**Completed deliverable: {F["pages"]} actual rendered pages**, comprising 12 preliminary pages (i–xii) and {F["pages"]-12} continuously numbered main/report pages (1–{F["pages"]-12}). The editable technical manuscript is complete for student/guide review. Administrative placeholders remain intentionally unfilled.\n')
p('- [Editable Word report](MLCN_Final_Mini_Project_Report.docx)\n- [Rendered PDF proof](MLCN_Final_Mini_Project_Report.pdf)\n- Supporting source, figures, audit evidence and render checks: `reports/workspace/`.\n')
p('## Institutional compliance\n')
p('The complete 11-page institutional PDF was extracted and its visual pages inspected, including cover, approval, declaration, contents and publications samples. Its sample contents sequence governs the preliminary order where narrative instructions differ. The implementation guide was read and checked against current code.\n')
p('| Requirement | Status and evidence |\n|---|---|')
rows=[
('A4 portrait; single column','Pass. Both Word sections are approximately 21 × 29.7 cm (Word twip rounding only); all PDF pages are 595.30 × 841.89 points.'),
('Binding margin 3.75 cm; other margins 2.5 cm','Pass. Section XML verified. Text bounds and embedded image bounds checked against the printable area.'),
('Times New Roman, 12-point body; 1.5 spacing','Pass. Normal style is Times New Roman 12 pt, line spacing 1.5. Paragraph separation is explicitly set; headings use real Word styles.'),
('Single spacing in specified material','Pass. Abstract, declaration, approval, references, captions and table titles use single-spaced styles. No separate quotations or footnotes are used.'),
('Table/figure text at least 8 pt','Pass. Table text 8–12 pt; numbered table text 9–10 pt; captions 10–11 pt. Figure master lettering remains approximately 8 pt or larger at final scale.'),
('Institutional title and certificate samples','Pass with required placeholders. Institutional wording, hierarchy, logo and four unsigned faculty positions retained; no approval asserted. Declaration uses the sample wording and six unsigned student positions.'),
('Preliminary sequence','Pass. Title, approval, declaration, acknowledgement, contents, tables, figures, abbreviations, symbols, abstract, CO–PO matrix. Collaboration/certification page is not applicable without verified evidence.'),
('Preliminary Roman and main Arabic footers','Pass. Center-aligned PAGE fields; every rendered footer checked. Chapter 1 restarts at Arabic 1; numbering continues through Appendix, References and Publications.'),
('Abstract approximately 100–200 words',f'Pass. {M["abstract_words"]} words; single spaced.'),
('Five narrative chapters plus institutional appendices/references','Pass. Chapters 1–5 form the required narrative. Chapter 6 contains Appendix I–VI. Chapter 7 contains References / Literature Cited. Publications are separate.'),
('40–100 rendered pages',f'Pass. {F["pages"]} pages measured from the final PDF, not estimated from Word metadata. No blank pages or chapter-ending one-line spill pages remain.'),
('Updateable TOC, List of Tables and List of Figures','Pass. Three live TOC fields retained in DOCX and refreshed with LibreOffice before final save/PDF export. Seven chapter entries and caption destinations checked.'),
('Chapter-based figure/table numbers','Pass. 15 figure and 23 numbered table captions use SEQ fields by chapter; the separate publications table is Table P.1. In-text numbers are generated from one manifest.'),
('Caption positions and first textual reference','Pass. Titles above tables, captions below figures. All 38 numbered objects have an earlier explicit manuscript reference. Caption page locations verified in the PDF.'),
('Editable tables and pagination','Pass. 28 real Word tables: 23 numbered tables plus five preliminary tables/layouts. Header repetition and prevention of row splitting verified. Long tables may continue with repeated headers.'),
('Original diagrams and valid data charts','Pass. Nine original architectural/methodological diagrams and six evidence-based charts; SVG masters and 300-DPI PNG embeds. Institutional logo alone is extracted from the supplied sample.'),
('Academic language and abbreviations','Pass. Third-person narrative; abbreviations expanded and listed. The mandatory first-person declaration is an unsigned institutional template.'),
('Numbered references in citation order','Pass. Fourteen verified entries; first-occurrence order [1]–[14] checked in rendered main text. Journal volume underlined where applicable. Repository evidence is attributed through artifact paths and hashes.'),
('CO–PO matrix','Template supplied, mapping pending. Four provisional CO rows and 12 PO columns contain explicit pending markers; no actual mapping or scale invented.'),
('Publications table','Pass. Institutional five-column format; explicitly records that no candidate publication is verified.'),
('Physical submission requirements','Student/department handoff. Confirm guide corrections/signatures, soft binding and single-sided printing on white paper ≥70 GSM; library copy should be acid-free/neutral or ≥85 GSM as specified.')]
for a,b in rows:p(f'| {a} | {b} |')
p('\n## Final rendering and layout checks\n')
p('The report was created with python-docx and rendered with local LibreOffice 26.8.1.1. A Basic automation macro refreshes document fields and all indexes before saving the DOCX and exporting the PDF. PyMuPDF independently checks the exported pages. All pages were inspected in contact sheets, with full-size checks of preliminary samples, chapter transitions, technical diagrams, dense tables, charts and bibliography.\n')
p('The final checks verify seven chapter starts, every Roman/Arabic footer, all caption locations, citation order, three live index fields, 38 SEQ caption fields, image/text bounds, repeated table headers and non-splitting rows. No unresolved manuscript tokens, field errors or blank pages were found. See `workspace/qa_results.json`, `workspace/final_checks.json` and `workspace/rendered/`.\n')
p('| Chapter | PDF page | Printed page |\n|---|---:|---:|')
for n,v in F['chapter_pages'].items():p(f'| {n} | {v["pdf_page"]} | {v["printed_page"]} |')
p('\nWord may repaginate after placeholder edits, font substitutions or renderer changes. Refresh the complete TOC and both caption lists after edits, then re-export and check the page count before submission. Editing order or inserting new objects also requires regenerating/updating the literal in-text cross-references.\n')
p('## Verified metrics and provenance\n')
p('| Evidence | Source and verification |\n|---|---|')
for a,b in [
('Offline population','`models/xgboost_test_predictions.csv`: 251,812 rows with saved labels, all 24 finite features and winning-class confidence. All hard-label metrics independently recomputed.'),
('Model replay','`models/xgboost_ids_multiclass.json` and `models/xgboost_ids_features.json`: 521 rounds, best iteration 520, 24 ordered features, five ordered classes. XGBoost 2.1.4 replay has zero predicted-class disagreements.'),
('Historical evaluation','`models/xgboost_evaluation_results.json`, classification report and confusion-matrix CSV. Reconstructed confusion counts agree exactly with the supplied matrix.'),
('ROC/PR evidence','Full probabilities regenerated from the model and test features in `workspace/regenerated_probabilities.npz`; curve arrays in `workspace/curves.json`. Historical probabilities were not falsely inferred from a single confidence column.'),
('Training record','`Untitled-1.ipynb`, especially cells 54–57, and model metadata. Earlier notebook states are inconsistent; a clean top-to-bottom retraining and split lineage are not certified.'),
('Raw dataset inventory','Eight `MachineLearningCVE/*.csv` files counted: 2,830,743 rows. The profile artifact describes 2,518,112 selected rows, a different population.'),
('Saved laboratory validation','`logs/launcher/validation_report.txt` and `validation_detections.jsonl`: 1,159 genuine records, no per-flow fallback. Consecutive profile-block reconciliation retained in `workspace/saved_live_reconciliation.json`.'),
('Test execution','`workspace/test_run_unrestricted.txt`: 202 tests in 28.078 s, 196 passed, six failures, no errors. Initial restricted-sandbox socket errors were resolved by the authorized unrestricted rerun; the six failures persisted.'),
('Source preservation',f'{I["inventoried_files"]} substantive original files were hashed and checked again; changed files: {I["changed_files"]}. Application source, model artifacts and original logs were not edited.')]:p(f'| {a} | {b} |')
p('\n| Metric | Verified value |\n|---|---:|')
for k in ['accuracy','balanced_accuracy','macro_precision','macro_recall','macro_f1','weighted_precision','weighted_recall','weighted_f1','cohen_kappa','matthews_correlation_coefficient']:p(f'| {k} | {E[k]:.12f} |')
p(f'| Historical macro OVR ROC-AUC | {E["roc_auc_ovr_macro"]:.12f} |')
p(f'| Regenerated macro OVR ROC-AUC | {A["roc_auc_macro"]:.12f} |')
p(f'| Historical log loss | {E["log_loss"]:.12f} |')
p(f'| Regenerated log loss | {A["log_loss"]:.12f} |')
p('\nBrute Force: 906 true positives, nine false negatives, 799 false positives; precision 0.531378299, recall 0.990163934 and F1 0.691603053. All 799 false positives come from BENIGN rows. The older guide’s 1,338 figure is the total BENIGN error count across all attack classes, not the Brute Force false-positive count.\n')
p('The maximum absolute drift between regenerated and saved winning-class confidence is 0.000597418646. Runtime XGBoost 2.1.4 differs from recorded training metadata 3.4.1, while requirements constrain runtime below 3.0. Label equality therefore establishes replay consistency, not bitwise equality of all scores. The one recorded batch inference duration (3.160199 s, four threads) excludes loading and DMatrix construction and is not a live throughput benchmark.\n')
p('Saved profile opening-flow matches are BENIGN 298/298, Brute Force 4/5, DDoS 188/190, DoS 23/24 and Port Scan 115/119. Blocks were reconstructed using saved profile totals; original ProfileWindow objects and raw capture files were unavailable. These are selected-profile laboratory matches, not independently labelled network-wide detection accuracy. No new Windows/Npcap capture was performed. Mixed-source `detections.jsonl` records are excluded from genuine validation metrics.\n')
p('Current feature code uses microseconds for timing features and seconds for rates, so the historical seconds-versus-microseconds mismatch is repaired in this repository state. Remaining nonstandard feature semantics, notebook inconsistencies, class imbalance, potential concurrency/lifecycle issues and synthetic-display provenance are discussed explicitly in the report.\n')
p('## Figure inventory\n')
p('| Figure | Caption / subject | Printed page | Evidence |\n|---|---|---:|---|')
for v in F['inventories']['figures']:
 kind='Architectural/methodological; proposed elements labelled' if v['number'].startswith('3.') else 'Verified saved or regenerated data; provenance in caption and Chapter 4'
 p(f'| Fig. {v["number"]} | {v["title"]} | {v["printed_page"]} | {kind} |')
p('\n## Table inventory\n')
p('| Table | Title | Printed page |\n|---|---|---:|')
for v in F['inventories']['tables']:p(f'| {v["number"]} | {v["title"]} | {v["printed_page"]} |')
p('\nAdditional preliminary tables are the approval signature layout, declaration signature layout, abbreviations, symbols and pending CO–PO matrix. They are intentionally unnumbered.\n')
p('## Citation and patent verification\n')
p('Online verification used original papers, author/institution-hosted pages, dataset providers, official Gemini documentation and Google Patents publication records. Fourteen sources are cited; no DOI or patent identifier was invented. Where publisher access was unavailable, the report uses verified arXiv, university-hosted or dataset-provider records and omits unverified bibliographic fields.\n')
p('| Citation | Verified source | Verification scope |\n|---|---|---|')
status={'sommer':'Original paper hosted by a university; authors, title, venue and argument checked.','cic2017':'Official UNB dataset page and associated-paper metadata; five-day collection checked.','xgb':'Original arXiv record and linked conference DOI.','normalization':'USENIX paper/venue record.','ddos2019':'Official UNB dataset page and associated-paper metadata.','ctu13':'Dataset-provider description; comparison only, not MLCN training input.','engelen':'Author research-group publication page, paper metadata and DOI.','arp':'Official USENIX publication page and paper metadata.','pr':'Original PLOS article, DOI and journal metadata.','shap':'Original arXiv record; attribution-method discussion.','lime':'Original arXiv record; local-surrogate discussion.','gemini':'Official structured-output documentation; accessed 21 October 2026. Proposed design only; no API call or implementation claim.','patent1':'Publication ID, inventors, title, priority/publication dates and relevant technical description checked.','patent2':'Publication ID, inventors, title, priority/publication dates and relevant technical description checked.'}
for c in M['citations']:p(f'| [{c["number"]}] | [{c["text"]}]({c["url"]}) | {status[c["key"]]} |')
p('\nPatent search terms combined “network intrusion detection”, “machine learning”, “flow features”, “real-time classification” and “adaptive representation”. Verified records: US12143406B1 (published 12 November 2024, priority 1 September 2022) and US20220021695A1 (published 20 January 2022, priority 9 November 2018). This is a limited technical related-work review, not an exhaustive patent landscape, novelty determination or freedom-to-operate opinion. No candidate publication is asserted.\n')
p('## Required student and guide inputs\n')
p('- Student names, roll numbers and actual number of candidates; remove unused declaration positions.\n- Branch and department; guide, co-guide if applicable, coordinator and head of department names.\n- Actual signatures and approval after authorized review; the supplied templates are unsigned.\n- Acknowledgements based on actual assistance, funding and any required disclosure of document-generation support.\n- Department-approved CO/PO definitions, row/column count, mappings, correlation rubric, evaluator and approval date.\n- Confirm submission date and academic year: 2025–26 is retained from the supplied institutional template, while repository inspection occurred in October 2026.\n- Supply collaboration certificates or genuine publication records only if applicable; none were verified.\n')
p('## Limitations and completion boundary\n')
p('The document-generation workflow is complete: editable DOCX, compatible rendered proof, original figures, verified evidence and validation record are supplied. Formal institutional approval cannot be completed without the student/faculty inputs above. Six existing repository tests fail in synthetic-result labelling/presentation; these failures are documented rather than repaired because application-source changes were prohibited.\n')
p('Offline model replay does not certify clean retraining, independent test provenance, live capture performance or deployment generalization. The saved notebook has inconsistent earlier outputs, and possible preprocessing-before-split leakage is discussed. Laboratory logs have narrower provenance than an independently labelled capture dataset. Gemini XAI and optional SHAP integration remain proposed and unmeasured.\n')
p('Final rendering was verified with LibreOffice, not Microsoft Word itself. The DOCX retains editable paragraphs/tables, styles, fields and images; SVG figure masters are available separately. Placeholder edits may change pagination. Physical printing, binding, signatures, university acceptance and any publication status remain outside digital validation.\n')
p('## Reproduction and artifact integrity\n')
p('Report-only scripts are retained: `audit.py`, `check_saved_live.py`, `make_figures.py`, `report_data.py`, `manuscript.md`, `generate_report.py`, `install_render_macro.py`, `render_macro.bas`, `qa_report.py`, `final_checks.py` and `write_validation.py`. The local renderer, profile and Python environment are confined to the report workspace. Run audit regeneration only when intentionally updating evidence; it may produce a different single-run timing.\n')
p('For document-only regeneration from the repository root, run `PYTHONDONTWRITEBYTECODE=1 reports/workspace/venv/bin/python reports/workspace/generate_report.py`, then the local LibreOffice `macro:///Standard.Module1.RenderReport` with `lo_profile`. Run `qa_report.py`, `final_checks.py` and `write_validation.py` with the same report Python. Regeneration overwrites the report, so preserve any later manual student edits before running it.\n')
p(f'- Final DOCX SHA-256: `{F["docx_sha256"]}`\n- Final PDF SHA-256: `{F["pdf_sha256"]}`\n- Original file hashes: `workspace/repository_inventory.json`\n- Final original-file integrity result: `workspace/source_integrity_check.json`\n')
(R/'MLCN_Report_Validation.md').write_text('\n'.join(out));print(R/'MLCN_Report_Validation.md')
