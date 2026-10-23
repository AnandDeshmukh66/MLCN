# 1 Introduction
## 1.1 Background and context
Machine Learning Cybersecurity Network (MLCN) is a laboratory implementation of flow-based network intrusion detection. An intrusion detection system (IDS) observes activity and identifies patterns that warrant investigation. A network IDS derives these observations from communication traffic. It differs from a preventive control because a classification does not itself block a connection or establish that a compromise occurred. MLCN connects packet capture, parsing, conversation assembly, numerical feature extraction and supervised classification in one executable processing chain.

The practical difficulty is maintaining agreement between the data representation used during model development and the representation produced by a running network monitor. A high score on previously extracted rows cannot demonstrate that live packets are grouped, measured and classified correctly. Sommer and Paxson [@sommer] identify the gap between controlled machine-learning evaluations and operational intrusion detection. In MLCN, this concern becomes concrete through timing units, payload accounting, flow termination and the distinction between genuine model predictions and demonstration output.

The present investigation examines the repository at commit 95407efc1f5d2b413abc36b24824481df97f7306, together with the local files available during the audit of 21 October 2026. The supplied implementation guide provides orientation, but current executable code and saved artifacts determine the technical findings. The report is an assessment of the observed implementation and its evidence, rather than a claim that every feature mentioned in the root README has been completed. The report follows the supplied institutional academic-year template, 2025–26; the actual submission date remains subject to student confirmation.

## 1.2 Network traffic and flow-based classification
Individual packets carry addresses, protocol identifiers, flags and payload. Many useful indicators depend on relationships among packets: the balance of requests and responses, elapsed time, inter-arrival gaps and characteristic message lengths. A bidirectional flow groups packets belonging to the same pair of transport endpoints and protocol. Aggregating such packets provides a compact representation for a classifier, while retaining enough temporal and directional structure for several common traffic categories.

The Canadian Institute for Cybersecurity (CIC) publishes CIC-IDS2017 as an intrusion-detection dataset with packet captures and labelled flow records [@cic2017]. The local MLCN workspace contains eight MachineLearningCVE comma-separated-value (CSV) files associated with that dataset and a notebook that selects five output classes. The measured unit of evaluation is a row representing a flow. The 2,830,743 rows found across these files must therefore not be described as an equivalent number of captured packets.

The implemented classifier predicts BENIGN, Brute Force, distributed denial of service (DDoS), denial of service (DoS), or Port Scan. BENIGN is the non-attack class, so the system contains four attack labels and one normal label. These classes do not cover all hostile activity. The notebook excludes other original categories, including Bot, Web Attack, Infiltration and Heartbleed, from the final five-class task. A prediction is consequently a choice within a restricted label vocabulary, not an open-ended assessment of all network threats.

## 1.3 Motivation and problem statement
The project is motivated by the need to make a trained network classifier observable as a complete system. A classifier deployed without documented packet semantics can receive plausible-looking but incompatible inputs. Conversely, a functioning capture interface can produce no useful predictions if flows never reach the completion boundary or if traffic falls outside the model’s classified protocols. Both types of failure can be hidden by a user interface that displays a desired profile instead of the actual detector output.

The problem addressed is to implement and assess an auditable conversion from observed network packets to a fixed 24-feature vector and a five-class prediction. The associated research questions are whether the repository preserves a consistent feature contract; whether its saved offline results can be independently reproduced; what the available laboratory records establish about live operation; and what additional evidence is necessary before an explanation service can responsibly describe a detection.

Extreme Gradient Boosting (XGBoost), developed by Chen and Guestrin [@xgb], supplies the tree-ensemble classifier. Its use is technically appropriate for structured numerical inputs, but the algorithm’s general success does not establish performance on an unseen network. The report therefore treats algorithm selection, implementation correctness, statistical evaluation and deployment validity as separate questions. This separation also prevents a demonstration profile match from being mistaken for independently labelled attack detection.

## 1.4 Scope and boundaries
The verified scope includes five connected processing modules, a trained XGBoost artifact, a training/evaluation notebook, local CIC flow data, a bounded traffic generator, receiver services, a Windows launcher, a Streamlit operations console, validation utilities and tests. The pipeline retains genuine results in memory and can emit structured detection records through its command-line interface (CLI). A separate demonstration transformation can alter displayed predictions when explicitly enabled or enabled by launcher defaults; its presence is central to interpreting the evidence.

The project does not verify network-wide visibility, high-volume capture reliability, autonomous remediation, authentication of an attacker, identification of malware families or generalization to arbitrary environments. The implemented feature vector contains no direct application credential content. The Brute Force generator produces labelled laboratory request/deny exchanges rather than guessing real credentials. The DDoS-labelled profile is bounded local traffic from the generator, so it is not evidence of a distributed attack campaign or a service outage.

Explainable artificial intelligence (XAI) using Gemini is included as a proposed extension. No implemented Gemini request path, model-attribution service or incident-report generation module is established by the source audit. A proposal is developed in Chapter 3 with explicit contracts and acceptance criteria. The application source is preserved during this reporting investigation; measured defects and limitations are documented instead of being silently repaired.

## 1.5 Objectives and contributions
The investigation has six objectives: trace the complete executable processing path; document the exact feature semantics; establish provenance for model-development and evaluation artifacts; reproduce available offline metrics; distinguish saved live validation from simulations and fabricated display values; and specify a grounded explanation workflow. Each objective is evaluated through code inspection, artifact checks or an explicitly identified design analysis.

The implementation contribution is the integration of packet capture with a schema-constrained five-class detector and a controlled laboratory demonstration environment. The reporting contribution is an evidence-based account of that system. It includes corrected interpretation of the confusion matrix, confirmation that the previously documented timing mismatch is repaired in current code, recognition of notebook execution inconsistencies, and identification of demonstration-source labelling failures in the test suite.

Table [[tab:objectives]] maps the objectives to evidence and appropriate completion claims. A distinction is maintained between a capability implemented in code and a capability validated under representative deployment conditions. This distinction permits useful conclusions about engineering integration without extending the offline accuracy claim to unmeasured operational settings.

[[TABLE:objectives]]

## 1.6 Investigation method and evidence hierarchy
The institutional PDF determines formatting and report organization. Repository code and machine-readable artifacts determine technical claims, followed by the implementation guide where it remains consistent. External literature supplies methodological context and independently verifiable related work. The audit records file hashes, model metadata, local dataset row counts, complete saved evaluation predictions and the results of the repository test suite. Generated plots use these artifacts or regenerated probabilities from the saved model.

Three evidence levels are used throughout. Recomputed findings arise from execution during this audit, including all saved-label metrics and regenerated probability curves. Recorded findings arise from existing notebook outputs or laboratory logs whose original collection process is not rerun. Proposed elements describe future behavior and contain no measured performance claim. An architectural figure explains software relationships; an experimental figure summarizes a specified population of observations.

## 1.7 Organization of the report
Chapter 2 reviews literature and patents. Chapter 3 documents the implementation and proposed Gemini design. Chapter 4 analyses offline results, laboratory records and test failures. Chapter 5 presents conclusions and future work. Chapter 6 supplies technical appendices, and Chapter 7 lists references, followed by the publications table.

# 2 Review of Literature
## 2.1 Review strategy
The review concentrates on work that helps assess the implemented task: flow-based supervised classification, tree ensembles, traffic-data quality, imbalanced evaluation and explanations. Sources are checked through original papers, author-maintained research pages, dataset-provider websites and patent publication records. Search terms include “machine learning network intrusion detection”, “flow classification”, “CICIDS2017 feature extraction”, “precision recall imbalanced datasets” and “adaptive network intrusion detection patent”. Verification is performed on 21 October 2026.

The review is selective rather than exhaustive. It does not combine accuracy figures from incompatible datasets into an apparent league table. Differences in labels, class balance, sampling, preprocessing and train/test separation can dominate an algorithm comparison. The comparisons below instead identify methodological choices and their relevance to MLCN. Numerical comparisons within this report are restricted to the same saved evaluation population or are clearly labelled as results from a different evidence level.

## 2.2 Intrusion-detection approaches and operational context
Signature-based detection searches for predefined evidence of known activity, whereas supervised classification learns relationships between labelled examples and outputs. Anomaly detection estimates a reference distribution and flags deviations. These approaches answer different questions: deviation from a baseline need not be malicious, and membership in a learned attack class does not establish the precise cause of an event. MLCN implements supervised multiclass classification, even though parts of its motivation use the broader language of anomaly detection.

Sommer and Paxson [@sommer] emphasize the difficulty of transferring machine learning into open operational environments. Their discussion motivates a requirement for realistic benign traffic and an understanding of the cost of errors. The present report applies that requirement by examining Brute Force precision separately from aggregate accuracy and by refusing to treat generated laboratory labels as independently established truth.

Handley, Paxson and Kreibich [@normalization] study ambiguity between traffic observed by a network monitor and traffic interpreted by endpoints. Their traffic-normalization work is conceptually different from MLCN’s statistical classifier, but it highlights why capture semantics matter. The local pipeline parses packets independently and does not reconstruct complete application sessions. Its predictions therefore inherit uncertainty from missing packets, segmentation, reordering and visibility across interfaces.

## 2.3 Boosted trees and the implemented model choice
Chen and Guestrin [@xgb] present XGBoost as a scalable tree-boosting system with regularization and engineering techniques for efficient learning. For MLCN, the relevant property is the ability to model nonlinear relationships among numerical flow features without adding a learned scaling stage. The repository’s final training cell uses a multiclass probability objective and histogram-based tree construction. These are code-verified choices, not deductions from the article.

A single decision tree offers a small rule structure but may be sensitive to training variation. A random forest averages multiple trees, while boosting constructs an additive ensemble whose later steps reduce the objective remaining after earlier steps. A neural network can represent complex interactions but introduces additional architectural and optimization choices. These are methodological alternatives; the repository does not supply matched final test artifacts for them. MLCN’s saved XGBoost results cannot establish superiority over these alternatives without controlled experiments.

The key empirical question is not whether boosted trees are powerful in general, but whether the chosen representation remains stable from training to live operation. A tree threshold learned in microseconds will not retain the same meaning if seconds are supplied. Likewise, a flag column interpreted as a packet count differs fundamentally from a dataset-specific first-packet binary encoding. The audited feature contract addresses these issues directly and is more consequential to this integration study than an unsupported comparison of classifier brands.

## 2.4 Traffic datasets and representation compatibility
CIC-IDS2017 provides a relevant source because its labelled flows and attack categories overlap the implemented classifier. The provider describes a five-day collection period, 3–7 July 2017, and traffic processed through CICFlowMeter [@cic2017]. The notebook’s introductory statement about seven days is therefore not retained as a verified dataset fact. Local CSV names and raw row counts corroborate the presence of the eight daily/attack-specific files; they do not independently certify the origin of every row against a provider checksum.

CIC-DDoS2019 broadens the discussion to multiple DDoS families and separately described collection periods [@ddos2019]. It is useful as a future external-domain evaluation source, but its inclusion in documentation does not prove that it trained the saved MLCN model. Matching feature names across datasets does not establish matching extractor versions, label definitions or sampling conditions. The present model is therefore described in relation to the locally evidenced CIC-IDS2017 workflow.

The Stratosphere Laboratory’s CTU-13 dataset contains thirteen botnet scenarios and distinguishes botnet, normal and background traffic [@ctu13]. Its bidirectional Argus flow representation illustrates that “flow-based” does not mean schema-identical. MLCN’s five labels exclude a dedicated botnet class, and its 24-column CIC compatibility contract is not an Argus adapter. A credible cross-dataset study would need an explicit label harmonization and feature reconstruction procedure before evaluating transfer.

Engelen, Rimmer and Joosen [@engelen] identify problems in CICIDS2017 traffic generation, flow construction, extraction and labelling. Their study supports scrutiny of the measurement pipeline itself. For MLCN, reproducing historical extractor behavior may improve compatibility with a saved model while retaining peculiarities that should not be mistaken for universal networking definitions. The documented binary flag permutation and duplicated first payload in aggregate length statistics are reported as local compatibility rules, not generalized definitions of those feature names.

## 2.5 Evaluation under imbalance and distribution shift
Arp, Quiring, Pendlebury, Warnecke, Pierazzi, Wressnegger, Cavallaro and Rieck [@arp] review common pitfalls in machine-learning security research. Their recommendations motivate checking data provenance, evaluation design and the connection between a measured task and a security claim. The present audit finds a stratified row split in the notebook, along with preprocessing performed before splitting. This is stronger evidence than an unknown split procedure, but it leaves dependence among related flows and preprocessing leakage as concrete concerns.

Saito and Rehmsmeier [@pr] explain why precision–recall views are valuable for imbalanced classification. MLCN’s Brute Force class is only 915 of 251,812 test rows. Its high recall is compatible with low precision because a small fraction of the much larger benign population can create many false alerts. Reporting both receiver operating characteristic (ROC) and precision–recall (PR) curves helps expose the difference between score ranking and a selected decision rule.

An area under the ROC curve (ROC-AUC) summarizes ranking across thresholds; it is not a statement that every deployed alert has that probability of being correct. The current multiclass decision rule selects the greatest probability without a separate rejection threshold. Its precision is evaluated at that specific operating point. Probability calibration, threshold selection and out-of-distribution rejection would require their own validation protocol, preferably using a population representative of the intended deployment.

## 2.6 Explainability and narrative reporting
Lundberg and Lee [@shap] introduce SHapley Additive exPlanations (SHAP), an additive feature-attribution framework. Ribeiro, Singh and Guestrin [@lime] develop Local Interpretable Model-agnostic Explanations (LIME), based on local surrogate explanations. These methods seek to relate a model output to input features under their respective assumptions. Neither establishes that a suspicious network event caused an intrusion, and neither is verified as an implemented MLCN component.

A large language model (LLM) can translate supplied evidence into a readable incident narrative. That ability is distinct from calculating an attribution. A Gemini response should not invent a statement that “high SYN count caused the prediction” when no attribution was computed and the named column follows a nonstandard flag mapping. The proposed design therefore uses a factual evidence contract and reports attribution as unavailable unless a separate, validated method has produced it.

Google’s Gemini documentation describes schema-constrained structured output using JavaScript Object Notation (JSON) [@gemini]. Syntactic conformity is useful for reliable integration, but it cannot establish factual correctness. The proposal in Chapter 3 adds evidence identifiers, numerical consistency checks, explicit uncertainty and a deterministic fallback. This is a system-design recommendation for MLCN; no application programming interface (API) execution or explanation-quality result is claimed.

## 2.7 Critical comparison of the reviewed evidence
Table [[tab:literature]] summarizes the relationship between the reviewed work and the implemented project. The comparison concerns methodological relevance rather than copying published performance scores. It identifies where the current system has an implementation response and where empirical work remains necessary.

[[TABLE:literature]]

The literature supports treating an IDS as a measurement-and-decision system. In MLCN, packet parsing determines the observations, flow construction determines the unit of analysis, feature extraction determines the statistical meaning of inputs, and inference determines a restricted label. A dashboard or narrative service is downstream of these stages and cannot correct missing evidence simply by presenting a more confident explanation.

## 2.8 Related-patent search
An accessible patent search is performed through Google Patents using combinations of network intrusion detection, machine learning, flow features, real-time classification and adaptive representation. Two publications are selected because their claims and technical descriptions are directly relevant to the project. Publication identifiers, titles, inventors, dates and the cited technical concepts are checked on the publication pages. This is a bounded related-work search; it is not a legal opinion on novelty, validity or freedom to operate.

Powell, Drozdenko and Roodbeen’s US12143406B1 [@patent1], published 12 November 2024, describes real-time network intrusion detection using statistical measures and machine learning. Its discussion of similarity between training measurements and monitored traffic is relevant to MLCN’s feature-contract problem. MLCN uses a particular five-class XGBoost model and explicitly documented extraction semantics; those implementation choices alone do not establish a patentable distinction.

Papamartzivanos, Bifulco, Kambourakis and Gomez Marmol’s US20220021695A1 [@patent2], published 20 January 2022, describes adaptive intrusion detection through a learned representation of unlabelled traffic and modification of labelled training data. MLCN currently applies a fixed saved model and does not perform that adaptive representation-learning procedure. The comparison identifies adaptation to network changes as future research rather than a completed capability.

Table [[tab:patents]] records the verified publications and their limited relevance. Patent legal-status labels are not used as technical evidence, and no assertion of project patentability follows from the search. Further searches across patent families, claims and jurisdictions would be needed if a formal intellectual-property assessment were requested.

[[TABLE:patents]]

## 2.9 Research gap and investigation direction
The gap addressed by this project is the distance between an offline flow classifier and an inspectable packet-to-prediction implementation. The reviewed sources motivate measuring that distance through explicit semantics and realistic evaluation. The repository provides a useful integration case because it contains both strong offline results and laboratory mechanisms whose outputs have different evidentiary meanings.

The investigation therefore traces implemented handoffs, checks feature semantics, reproduces saved results and separates genuine laboratory evidence from display substitutions. It proposes an evidence-grounded explanation layer. Independent live-labelled captures, session-aware evaluation, improved Brute Force precision and reliable lifecycle handling remain the principal research needs.
# 3 Work Done / Present Investigation
## 3.1 Repository scope and evidence method
The repository audit covers application packages, configuration, models, data, images, tests, documentation, notebook contents and logs. The generated inventory records 133 substantive files after excluding version-control internals, virtual environments, operating-system metadata, bytecode caches and newly generated report files. Each included file is read and hashed; Python modules are additionally parsed for class and function definitions. The inventory is retained with the report-generation evidence, while selected interfaces are documented in Appendix II.

The most important artifacts are the saved model, its ordered feature/class metadata, the complete saved test prediction table, the evaluation summary, the confusion matrix and the training notebook. Source hashes associate the report with an exact local state. They do not establish who created an artifact or validate an external dataset download. The institutional PDF and implementation guide are also inventoried, with current code taking precedence wherever the guide has become outdated.

Existing image assets are inspected as project documentation but are not reused as technical evidence. The diagrams in this report are generated originally from the audited implementation. A Gemini-generated illustration in the assets directory does not establish an implemented Gemini integration. Similarly, the root README’s proposed explanation, incident database and reporting modules are separated from the implemented capture, classification and operations-console functionality.

## 3.2 Overall architecture
Fig. [[fig:architecture]] shows the complete implemented architecture and the proposed narrative extension. The generator sends controlled traffic to a receiver; capture observes packets rather than receiving reference medians from the profile file. The detector consumes features derived from completed flows. Genuine classification results are preserved before any optional display transformation. The Streamlit console reads persisted receiver records and displays the current run and recent flow history.

[[FIG:architecture|Overall MLCN architecture. Solid blocks show audited components; the dashed Gemini block is proposed. This is an architectural diagram, not a measured network topology.]]

The architecture has two important separations. First, traffic generation produces an experimental stimulus, while packet capture independently observes the resulting traffic. Second, the genuine prediction and the displayed prediction may differ when demonstration fallback is enabled. Scientific evaluation must follow the genuine result through both separations. A profile name or an attractive display card cannot replace either captured evidence or a classifier output.

## 3.3 Five-module processing pipeline and contracts
Fig. [[fig:pipeline]] expands the five connected modules. Module 1 captures raw Scapy packets. Module 2 produces PacketMetadata. Module 3 groups metadata into Flow objects. Module 4 computes an ordered FeatureVector. Module 5 produces a DetectionResult, and orchestration combines the flow, features and prediction in PipelineResult. These typed objects make responsibilities explicit and allow tests to enter the system at different boundaries.

[[FIG:pipeline|Five-module processing pipeline and typed handoffs. The pipeline orchestrator connects existing module APIs and retains the genuine combined result.]]

Table [[tab:contracts]] describes the main interfaces. Intermediate objects are immutable dataclasses where defined, but the active-flow accumulator is mutable. A completed flow retains all packet metadata, enabling feature recomputation without parsing the original Scapy packet again. This improves inspectability but also means memory use grows with retained packet histories and accumulated results, not merely with the number of active flow keys.

[[TABLE:contracts]]

## 3.4 Module 1: packet capture
PacketCaptureEngine in packet_capture/capture.py resolves an interface or a comma-separated interface list and invokes Scapy sniff with store=False and a one-second timeout. A Berkeley Packet Filter (BPF) expression can restrict traffic to a laboratory port or port range. The callback path capture_metadata is the integration interface used by the pipeline. Separate display-oriented methods preserve the packet-capture CLI and its ParsedPacket representation.

Single-interface capture runs directly; multiple interfaces create daemon worker threads. The implementation installs signal handlers only from the main thread, allowing background validation to start without an illegal signal registration. On Windows, Ctrl+Break support helps the launcher stop a child process group. Permissions and interface errors are surfaced through user-facing CLI messages. In contrast, callback exceptions are generally logged at debug level and suppressed so that capture can continue.

The use of store=False prevents Scapy from retaining its own full packet list, but it does not make the whole application constant-memory. The flow builder stores metadata and the pipeline retains completed results. Multiple interface workers can also call into shared flow state without an explicit pipeline lock. This is a code-level concurrency concern, not a measured corruption result. No packet deduplication, capture-loss measurement or global ordering queue is verified.

## 3.5 Module 2: packet parsing and normalization
The packet parser accepts a Scapy Packet and returns PacketMetadata or None. It normalizes timestamps to timezone-aware Coordinated Universal Time (UTC), validates Internet Protocol (IP) addresses, bounds port numbers, extracts Transmission Control Protocol (TCP) or User Datagram Protocol (UDP) fields, and records packet length. IPv4 time to live and IPv6 hop limit are exposed as metadata, together with TCP window information when applicable. These auxiliary fields are not all included in the 24-feature model vector.

Non-IP frames can produce metadata with absent addresses; such records are later unable to form a valid flow key. Malformed objects, unusable lengths and invalid addressing are skipped. TCP flags are normalized into a compact letter representation. The parser recognizes Internet Control Message Protocol (ICMP) for metadata purposes, but the integrated classifier subsequently excludes protocols other than TCP and UDP. Parsing support must therefore not be confused with classification coverage.

Fig. [[fig:packet_flow]] shows the transformation from packets into eligible flows. The parser distinguishes observed packet length from transport payload length. Payload accounting subtracts Scapy padding already represented in the transport payload and applies an IPv4 minimum-frame padding adjustment. This is a compatibility rule intended to align short-packet lengths with the historical CIC-derived representation. IPv6 does not follow that IPv4 padding branch. The report does not claim independent packet-capture equivalence for every protocol or platform.

[[FIG:packet_flow|Packet-to-flow transformation, completion and classification eligibility. Discard and completion rules are architectural conditions, not experimental detection rates.]]

## 3.6 Module 3: bidirectional flow construction
A FlowKey is constructed from source address, destination address, source port, destination port and normalized protocol. The endpoint pairs are sorted lexicographically, using a sentinel only when a port is absent. A packet and its reverse direction therefore map to the same dictionary key. Canonical endpoint ordering is a lookup convention; it is not a declaration that the smaller address is the client or that the key’s source endpoint initiated the connection.

The mutable _ActiveFlow stores the first arrival’s direction as its forward orientation and appends subsequent metadata. It tracks packet counts, observed byte counts, direction-specific counts and timestamps. Completion creates an immutable Flow with the packet tuple and a closed_by_fin flag where appropriate. Fig. [[fig:bidirectional]] separates the identity of the conversation from its direction convention. This distinction is necessary when explaining directional features or interpreting logs whose canonical source is the receiver port.

[[FIG:bidirectional|Bidirectional key construction and orientation. Canonical endpoint ordering and forward-direction anchoring serve different purposes.]]

The generic FlowBuilder defaults are a 60-second inactivity timeout, a 300-second maximum duration, 100,000 active flows and FIN termination disabled. The integrated pipeline overrides the maximum duration to 120 seconds and enables FIN termination through the feature contract. The launcher separately shortens inactivity to five seconds for laboratory runs. A report that quotes only the standalone class defaults would misdescribe the actual integrated system.

On each accepted packet, the builder first expires flows that have exceeded the inactivity limit relative to that packet’s timestamp. For an existing key, it also checks maximum age before appending. A FIN packet appended to an existing flow can close it immediately; a first packet starting a new flow is not subjected to the same post-append FIN branch. Capacity eviction selects the least recently seen active flow, and an explicit flush closes every remaining flow. TCP reset alone is not a configured termination condition.

The expiration scan traverses active flows, so add_packet is not constant-time in the number of active conversations. During a completely silent capture, no background timer in the builder independently expires idle flows. A later packet or explicit shutdown flush triggers completion. This explains why an idle timeout is not itself a guaranteed maximum alert delay. The same code also updates end_time in arrival order, whereas feature extraction later sorts packet timestamps; out-of-order arrivals can therefore create differences between displayed duration and the model’s duration feature.

## 3.7 Module 4: canonical feature engineering
The canonical contract is defined in feature_engineering/contract.py and re-exported by the schema module. It defines exactly 24 names, their order, units, integer-valued features, time constants, eligible protocols and special compatibility rules. The machine-readable data schema documents this contract as version 2.0.0. Fig. [[fig:features]] shows the calculation groups. Appendix I gives the complete ordered schema, and Table [[tab:featuregroups]] summarizes its interpretation.

[[FIG:features|Feature-engineering workflow under the current 24-feature contract. Timing features use microseconds; rates use seconds.]]

[[TABLE:featuregroups]]

### 3.7.1 Timing and directional measurements
Packets are stably sorted by integer microseconds derived from their timestamps. Feature direction is anchored to the earliest packet after sorting. This usually agrees with the flow builder’s first-arrival orientation but can differ when delivery order and timestamp order differ. The distinction is retained as an implementation limitation instead of being hidden behind the general phrase “first packet”. Empty packet sequences produce zeros, although the integrated classifier excludes flows with fewer than two packets.

For sorted timestamps t₁ through tₙ expressed in microseconds, duration is D = max(0, tₙ − t₁). Inter-arrival gaps are gᵢ = tᵢ − tᵢ₋₁. Flow IAT Mean averages all gaps, and forward/backward IAT means average gaps within their respective directions. IAT denotes inter-arrival time. Flow IAT Std uses the sample standard deviation with denominator m − 1 for m gaps, returning zero for fewer than two gaps. These units and denominators matter when reproducing thresholds in a trained model.

### 3.7.2 Payload lengths, rates and direction ratio
For each packet, the extractor uses payload_length when available and falls back to observed length otherwise. Directional totals sum payload bytes, and directional means divide by the relevant packet count. The overall Packet Length Mean and Packet Length Std use the series consisting of the first payload followed by all payloads. The first value is therefore counted twice, producing n + 1 observations. This is intentional local compatibility behavior and must not be rewritten as the ordinary mean of n packet lengths.

For nonzero duration, Flow Bytes/s = total payload bytes × 10⁶ / D and Flow Packets/s = n × 10⁶ / D. The displayed flow duration remains in seconds. If D is zero, the extractor supplies the recorded training rate-fill constants: 3715.0378579999997 payload bytes/s and 69.742244285 packets/s. These values preserve the documented preprocessing convention; they are not measurements of an instantaneous physical rate.

Down/Up Ratio is floor(n_b / n_f), with zero when no forward packets exist. It is not forward divided by backward, and it is not a fractional ratio. For example, three backward packets and two forward packets yield 1.0. This correction is important because the supplied guide describes the older inverse convention. The removal of Average Packet Size from the candidate schema is described as near-duplication, not exact algebraic equivalence under the current n + 1 length semantics.

### 3.7.3 First-packet flags and activity periods
The six feature columns named Flag Count are binary indicators of the first sorted TCP packet. The contract maps FIN Flag Count to R, SYN Flag Count to P, RST Flag Count to C, PSH Flag Count to S, ACK Flag Count to A, and URG Flag Count to F. The names thus preserve dataset-compatible column semantics rather than conventional names for accumulated TCP flags. Non-TCP packets contribute zero to these binary indicators. Any future explanation must use this mapping when describing what was actually observed.

Active and idle periods are derived from gaps greater than five million microseconds. Such a gap closes a preceding positive active span and is recorded as idle. The final active span is not added. If the flow was closed by FIN, the final closing packet is excluded from activity-state updates. A short uninterrupted flow can consequently have Active Mean equal to zero even though communication occurred. The feature is a statistic of recorded segmented periods, not the total amount of time the host was working.

### 3.7.4 Input validation and remaining semantic risks
FeatureVector enforces the vector length and provides mapping, tuple and list views. Integer-schema values are converted through integer coercion and then represented as floats. The model boundary verifies that all supplied values are finite. A raw sequence has no semantic names attached beyond its position, so order correctness remains the caller’s responsibility. The from_mapping helper fills missing names with zero; this convenience is not a substitute for verifying completeness in an external ingestion service.

The current code repairs the guide’s seconds-versus-microseconds mismatch. Feature names, units and order agree across the contract and model metadata. However, this establishes a local contract rather than universal equivalence to every historical CICFlowMeter output. Timing resolution, retransmissions, padding, packet loss, FIN behavior and mid-flow starts can still alter the representation. Independent packet-level reference captures remain necessary to validate those boundary cases.

## 3.8 Module 5: XGBoost inference
MLDetectionEngine loads the saved JSON booster and feature/class metadata before processing traffic. It verifies exact feature order and exact class order. The class sequence is BENIGN, Brute Force, DDoS, DoS and Port Scan, corresponding to identifiers zero through four. The loader prefers models/ and retains support for an older xgboost/ artifact directory. A dedicated import helper avoids confusing that local directory with the installed Python library.

Fig. [[fig:inference]] shows the inference path. Values are converted to a one-row float32 array, wrapped in an XGBoost DMatrix with feature names, and passed to the booster. The best_iteration attribute is 520, so inference uses the half-open iteration range (0, 521). The audited model contains 521 boosting rounds. The highest of five probabilities supplies the predicted class and confidence. No scaler, one-hot encoder or principal-component transformation is loaded by the runtime detector.

[[FIG:inference|XGBoost loading and inference. Confidence is the maximum model probability and is not a calibrated probability of a real intrusion.]]

The predict_many method loops over rows and invokes single-row prediction; it is not a vectorized batch API. A convenience predict function constructs a new engine per call, whereas the integrated pipeline reuses one engine. The distinction affects runtime cost. Model-load and feature-validation errors are explicit, while try_predict can suppress unexpected prediction failures after validation. A failed inference is therefore not equivalent to a BENIGN prediction and should be counted separately in any operational monitor.

## 3.9 Notebook training and evaluation workflow
The notebook contains a substantive training workflow, contrary to the older guide’s claim that training code is absent. It loads eight local CIC CSV files, strips column whitespace, removes duplicates, handles invalid rates, maps labels and selects 24 features. The final selection merges FTP-Patator and SSH-Patator into Brute Force, combines four DoS subclasses, renames PortScan and excludes categories outside the five-class task. The notebook retains historical outputs from inconsistent states, so source code and saved outputs are identified separately.

The split cell specifies an 80% training partition and a 20% temporary partition, then splits the latter equally into validation and test sets. Both operations stratify by class and use random_state=42. Recorded sizes are 2,014,489 training rows, 251,811 validation rows and 251,812 test rows. Fig. [[fig:training]] depicts this recorded methodology and the separate audit replay. The diagram does not claim a fresh end-to-end retraining run.

[[FIG:training|Recorded training/evaluation methodology and audit replay. Early notebook outputs are inconsistent; the saved test artifacts and regenerated inference are independently checked.]]

Only the training partition is subsequently undersampled. BENIGN is reduced to 150,000 rows, all recorded attack rows are retained, and the combined training population becomes 487,388. Balanced class weights are computed on this population and passed as sample weights. The recorded Brute Force weight is approximately 13.313, much larger than the BENIGN weight of approximately 0.650. This provides a plausible mechanism for favouring rare-class recall, although the causal effect on false positives cannot be isolated without an ablation.

Table [[tab:training]] records the final training-cell parameters. Early stopping monitors validation_1 multiclass log loss with a patience of 100 rounds and save_best=True. The metadata records XGBoost 3.4.1, while requirements.txt constrains runtime XGBoost to versions below 3.0. The audit therefore explicitly records its installed version, 2.1.4, and verifies the resulting predictions rather than assuming identical floating-point probabilities across versions.

[[TABLE:training]]

## 3.10 Pipeline orchestration, completion and output
IntrusionDetectionPipeline accepts raw packets, parsed metadata, batches or live capture. It owns the builder, feature engine and detector, exposes counters, and supports reset, flush and close. Completed flows must contain at least two packets and use TCP or UDP to be classified. A pipeline detection combines the completed flow, feature vector and genuine detector result. The genuine result is appended to internal results before the optional display transformation is applied to the callback copy.

The CLI can print class, confidence, endpoint key, observed packet and byte counts, duration and all five probabilities. Its --detections-log option appends one JSON object per displayed result, including genuine prediction fields and a demo_fallback indicator. The serialization does not include the complete feature vector, even though the in-memory PipelineResult retains it. Existing JSON Lines (JSONL) files therefore support prediction analysis but cannot fully reconstruct the feature evidence for an explanation service.

The pipeline catches feature-extraction or detection exceptions and continues. Such failures are debug-logged but do not have a dedicated failed-flow counter. The accepted-packet counter increments before checking whether usable addressing exists, and can therefore include metadata later rejected by the flow builder. These details limit the interpretation of counters as throughput or success metrics. A future operational version should distinguish parsed, flow-eligible, classified, intentionally skipped and failed observations.

## 3.11 Traffic profiles, parameter mapping and generation
The profile JSON stores empirical reference statistics and a source-population count of 2,518,112. profile_loader reads medians and discriminative-feature blocks, and parameter_mapper converts those values into bounded connection, delay and payload settings. The profile numbers are reference statistics, not the actual observed 24-feature vector. Fig. [[fig:generator]] shows the separation between the profile, traffic stimulus, capture and detector.

[[FIG:generator|Generator/receiver interaction and evidence paths. Profile reference medians do not bypass capture or enter the detector as synthetic feature vectors.]]

Five generator classes implement distinct laboratory shapes. BenignTrafficGenerator performs ordinary request/response exchanges. PortScanTrafficGenerator uses TCP connect probes over a bounded range; a field named send_syn_only does not turn it into a raw SYN-only packet generator. BruteForceTrafficGenerator uses a line-oriented laboratory session with six request/deny exchanges. DDoSTrafficGenerator requests a small laboratory path with bounded concurrency, while DoSTrafficGenerator sends browser-like requests in bursts separated by pauses.

The configured page response is 11,600 bytes; the DoS request builder targets 330 bytes and the DDoS request is a short Hypertext Transfer Protocol (HTTP) request. These shape choices are implementation details used to approximate selected training-flow patterns. They should not be interpreted as genuine exploitation or as proof that the response semantics match every member of a dataset attack class. The sender’s packets_sent counter records application send operations and is not a measured count of packets on the wire.

The controller validates a private/local target, port and duration, manages a stop event and worker thread, records progress, and writes a structured generator run log. Target checks reject public destinations and support a documented private/loopback policy. The configuration declares caps of 300 seconds, 20 connections/s, 50 packets/s, ten concurrent connections, fifty ports and 512 payload bytes. These are laboratory controls; not every constant is a packet-level enforcement mechanism, and receiver page bytes are distinct from the generator’s payload parameter.

## 3.12 Receiver services and validation modes
LabEchoServer binds a laboratory endpoint and handles connections in worker threads. It returns a fixed page for the configured page paths and responds to laboratory authentication-like lines with a denial line. receiver_server exposes this service as a CLI for a separate receiver. Connectivity helpers probe endpoint availability and offer platform-specific capture guidance. A TCP service must be available for request/response profiles, whereas a closed-port response can be meaningful to a port-probe profile.

LocalValidationRunner can start the actual pipeline on loopback and collect in-memory results. It converts them into ValidationRecord objects containing target profile, prediction, probabilities and all observed feature values. Its stop method closes the pipeline and joins the worker with a timeout, but the pipeline’s locally created capture engine is not exposed for an explicit stop request. This is a lifecycle concern: closing the classifier path does not itself demonstrate that a background sniff loop has terminated cleanly.

The launcher’s validation utility runs profiles sequentially, records time windows and compares genuine predictions for connection-opening flows. Its opening-flow criterion is an initial flag string exactly equal to S. The denominator therefore excludes closing-handshake tails and other flows that do not satisfy the criterion. This restricted match fraction is useful for a controlled demonstration, but is not the same statistic as end-to-end accuracy over all classified flows or recall against independently verified malicious events.

## 3.13 Windows launcher and process lifecycle
start_mlcn.bat selects an available project Python executable and invokes mlcn_launcher. The launcher checks platform, Npcap availability, administrative requirements, interface discovery, model readiness and relevant ports. It identifies the local adapter and the Npcap loopback device, starts the receiver service and pipeline, and manages the Streamlit child process. Child environments configure UTF-8 output, the single-PC mode, the session file and demonstration fallback behavior.

The process wrapper gives each child an independent process group where supported. Shutdown attempts an interrupt, then termination and finally kill if required. The launcher’s default LaunchConfig enables demo_fallback, uses lab port 8080 and a fifty-port span, and sets inactivity to five seconds. A --no-demo-fallback launcher option is available. Reproducible scientific validation must record this option or equivalent environment setting, rather than relying on a launcher default intended for presentation.

## 3.14 Streamlit console and demonstration provenance
The current Streamlit application is a two-panel operations console. The left panel controls loopback generation at 127.0.0.1. The right panel reads receiver JSONL records and presents a final session result or latest flow, probabilities, flow metadata and recent history. The reader tails at most 512,000 bytes, tolerates incomplete JSON lines and filters by recording time. This is implemented receiver visibility, correcting the older guide’s claim that Streamlit has only generator-side status.

Demonstration fallback creates a synthetic five-class probability distribution when the genuine class differs from the selected profile. Its synthetic selected-class confidence is sampled between 0.91 and 0.975. The genuine prediction remains available separately. Session verdicts apply a 90% opening-flow match rule and also check the aggregate class. Synthetic distributions represent presentation behavior and cannot be included in accuracy, calibration or explanation-quality measurements.

The source currently names the fallback result “Fetching RESULT” and its disclaimer “Interpolated Values”, while older log records use “FABRICATED DEMO RESULT”. The dashboard’s fabricated property recognizes an “Interpolated Values” source or a per-flow demo_fallback boolean. A session record using “Fetching RESULT” lacks that boolean, creating a risk of mislabelling its displayed source. The six observed test failures include expectations affected by this terminology and presentation drift. The report therefore uses the explicit term synthetic demonstration output whenever such values are discussed.

## 3.15 Test architecture and integration evidence
The tests cover packet normalization, module handoffs, canonical keys, timeouts, feature calculations, schema validation, real saved-model inference, pipeline lifecycle, laboratory generators, launcher behavior, dashboard parsing and fallback logic. Some tests patch sniff or construct packets directly. tests/lab_traffic_simulation.py explicitly describes its packet sequences as approximations of Windows loopback behavior. Successful tests using those sequences establish consistency under the simulated inputs, not successful capture from a physical interface.

The audit executes the complete unittest suite. An initial sandboxed run encounters three socket-binding errors in addition to six assertion failures. A rerun with loopback sockets permitted removes the environment errors and produces 196 passing tests and six failures out of 202. The tests that load the real classifier and exercise the simulated profile chain pass in that run. Chapter 4 interprets the failures and keeps this evidence separate from saved Windows-oriented validation records.

## 3.16 Proposed Gemini XAI architecture
The proposed workflow is genuine prediction plus associated evidence, followed by a structured Gemini request, validated explanation generation and a human-readable report. Fig. [[fig:gemini]] identifies every new element as proposed. It operates after classification so that a language-model timeout cannot delay or replace the underlying detector. No network call to Gemini is made during this investigation, and no application implementation is added.

[[FIG:gemini|Proposed Gemini explanation architecture. Dashed blocks are unimplemented design elements; only genuine evidence is eligible for explanation.]]

### 3.16.1 Input contract and grounding
A proposed EvidenceEnvelope contains an evidence identifier, capture timestamp, flow identifier, model hash, feature-schema version, genuine class, all five genuine probabilities, feature values with units, capture-quality flags and provenance status. The classification component supplies these fields from the in-memory result or an expanded future evidence sink. The current JSONL export is insufficient for complete feature grounding because it omits the feature vector. Appendix V provides the proposed contract as an interface specification rather than as a recorded API payload.

The envelope explicitly rejects a synthetic displayed distribution as model evidence. If a demo_fallback record is encountered, the service may use separately verified genuine fields only when their provenance is complete; otherwise it returns an insufficient-evidence summary. Feature values are validated for finiteness, order, units and schema version. The flag mapping is included in explanatory metadata so that a column name cannot be interpreted as a conventional count without checking its definition.

Each explanatory observation cites an evidence identifier and a field path. For example, a statement about Flow Duration cites its microsecond value and any displayed conversion to seconds. The system does not claim that a feature caused the decision merely because its value is large. Optional SHAP contributions would arrive through a separate attribution object with its method, model version, background/reference definition and output space. If absent, the report states that feature attribution was not computed.

### 3.16.2 Request and response design
The proposed request separates trusted instructions from untrusted evidence values. A versioned instruction specifies the task, permitted evidence, class vocabulary, uncertainty language and JSON response schema. Evidence is serialized as data rather than concatenated into free-form instructions. A model identifier is configured and logged at deployment time; the report avoids selecting an unverified future model name. Structured output is used for parseability, with semantic validation performed locally after generation.

The response contains a factual summary, evidence-linked observations, limitations, alternative explanations, recommended human checks and a provenance block. It repeats the genuine prediction without changing its label or probabilities. It avoids unsupported statements about attacker identity, successful compromise, credential theft, attack campaign scale or business impact. A recommendation such as reviewing an associated service log is distinguishable from an assertion that the service was compromised.

### 3.16.3 Privacy, uncertainty and reliability
The proposed privacy boundary excludes raw payloads, credentials and unnecessary host identifiers. Where endpoint continuity is useful, pseudonymous identifiers can preserve within-session relationships without disclosing actual addresses. Retention, provider data-handling terms and authorization for cloud processing must be selected for the deployment environment. These are proposed controls, not verified properties of an existing Gemini integration.

Reliability requires timeout limits, bounded retries, an input-size limit and an idempotent evidence identifier. A cache key includes model, schema and prompt versions to prevent reuse of an explanation for different evidence. Invalid JSON, unknown evidence references, altered probabilities or ungrounded factual claims cause the response to be rejected. The fallback is a deterministic template showing the verified class, scores and limitations. The design does not allow the language model to issue firewall changes or launch diagnostic traffic autonomously.

### 3.16.4 Explanation acceptance criteria
A proposed evaluation set should include correct and incorrect detections, low-confidence cases, missing features, corrupted records, synthetic fallback records and prompt-like text embedded in untrusted fields. Acceptance measures include factual consistency with the envelope, evidence-reference coverage, numerical fidelity, privacy leakage, refusal on insufficient evidence, and analyst usefulness. Latency and API cost are measured separately from capture-to-classification latency. No accuracy, usefulness score or runtime estimate is assigned before those experiments exist.
# 4 Results and Discussions
## 4.1 Evidence populations and experimental setup
Four populations must be distinguished. The raw local CSV collection contains 2,830,743 flow rows. The profile artifact describes a selected five-class population of 2,518,112 rows. The saved offline test table contains 251,812 rows. The saved launcher validation file contains 1,159 flow records from a loopback-oriented laboratory run. These populations have different origins, filtering rules and labels. Their metrics are not pooled into a single accuracy figure.

The audit runs under Python 3.9.6 on macOS 26.7.1 with an ARM64 platform, XGBoost 2.1.4 and scikit-learn 1.6.1. It loads the existing model without training or modifying it. The 24 saved test columns are converted to float32 and passed to the booster using rounds zero through 520. The original evaluation summary and notebook record XGBoost-related metadata separately. No Windows/Npcap capture is newly performed on this macOS host.

Table [[tab:evidence]] records the source and interpretation of each result family. All saved test features are finite. Recomputed predictions agree with every saved class label, and the confusion matrix reconstructed from the saved labels exactly matches the provided matrix. The probability scores differ slightly between the audit runtime and the stored winning-class confidences, so historical summary metrics and regenerated score-based results are labelled distinctly.

[[TABLE:evidence]]

## 4.2 Class distribution and imbalance
Fig. [[fig:distribution]] shows the verified test distribution on a logarithmic count axis, with exact counts and class percentages. BENIGN accounts for approximately 83.25% of the test population, whereas Brute Force accounts for approximately 0.36%. This disparity is large enough that overall accuracy can remain high even when the rare class generates substantial false positives. The logarithmic axis is used only to make all class counts visible; it does not alter the values used for metrics.

[[FIG:distribution|Verified class distribution in models/xgboost_test_predictions.csv, n = 251,812. Bar heights use a logarithmic count axis.]]

The test set preserves the original selected-population proportions rather than the undersampled training proportions. This is appropriate for measuring performance on the recorded evaluation distribution, but it also exposes the consequences of the training reweighting strategy. A model that gives the rare class more training influence can achieve high recall while assigning too many benign examples to that class. The present data support describing that trade-off; they do not establish which particular hyperparameter caused it.

## 4.3 Overall offline classification results
Table [[tab:metrics]] reports the verified summary metrics. Accuracy is 0.9942377647, equivalent to 99.4238%, with 250,361 correct predictions and 1,451 errors. Balanced accuracy is 0.9955679604, equivalent to the mean of the five class recalls. Macro F1 is 0.9335848515, while weighted F1 is 0.9947219616. The lower macro score reflects the influence of the Brute Force class when each class receives equal weight.

[[TABLE:metrics]]

Precision for a class is TP/(TP + FP), recall is TP/(TP + FN), and F1 is twice the product of precision and recall divided by their sum. TP, FP and FN denote true positives, false positives and false negatives respectively. Accuracy weights every row equally, balanced accuracy weights each class recall equally, and weighted averages use class support. These definitions explain why high balanced accuracy can coexist with lower macro precision: balanced accuracy does not directly penalize the false-positive burden within a rare predicted class.

The saved multiclass log loss is 0.0244827153 and the saved macro one-versus-rest ROC-AUC is 0.9999122875. The regenerated values are 0.0244703876 and 0.9999122997 respectively. The maximum absolute difference between regenerated winning confidence and the saved Confidence column is approximately 0.00059742. This small probability drift does not change any winning class, but it is sufficient to justify identifying the runtime and avoiding a claim of bitwise reproduction.

## 4.4 Per-class results
Table [[tab:perclass]] presents precision, recall, F1 and support for every class. Fig. [[fig:performance]] provides a visual comparison of those same values. DDoS, DoS and Port Scan have high offline precision and recall in this saved population. Brute Force is the clear exception in precision and F1, despite its recall being close to 99%. The table supports a class-specific conclusion rather than a uniformly strong statement about all attack categories.

[[TABLE:perclass]]

[[FIG:performance|Per-class precision, recall and F1 reconstructed from saved offline labels. Brute Force precision is substantially below the other classes.]]

A support of 915 gives less evidence about the range of Brute Force behaviors than the 209,638 BENIGN rows give about the recorded benign population. Moreover, individual rows may not be statistically independent because multiple flows can arise from the same host, service or scripted activity. A simple binomial confidence interval would not address that dependence. The report therefore avoids presenting a narrow interval as a guarantee of cross-session or cross-network performance.

## 4.5 Confusion matrix and error analysis
Fig. [[fig:confusion]] visualizes the verified confusion matrix, and Table [[tab:confusion]] supplies its exact integer values in editable form. Rows are actual labels and columns are predicted labels. Colour is logarithmic to expose small error cells alongside the large benign diagonal. Matrix orientation is stated explicitly because transposing its interpretation changes the error analysis.

[[FIG:confusion|Verified offline confusion matrix. Cell annotations are exact counts; colour represents log10(count + 1). Rows are actual and columns predicted.]]

[[TABLE:confusion]]

Brute Force has 906 true positives, nine false negatives and 799 false positives. All 799 false positives originate from BENIGN rows. Consequently, 906/(906 + 799) = 53.1378% precision, and 46.8622% of Brute Force predictions in this test set are incorrect. The guide’s count of 1,338 false positives combines the entire benign error row across several predicted classes. That value is the number of BENIGN rows assigned to any attack label, not the Brute Force false-positive count.

The 1,338 BENIGN errors divide into 799 Brute Force, 46 DDoS, 398 DoS and 95 Port Scan predictions. They account for approximately 92.21% of all 1,451 errors. Other classes mainly lose a small number of rows to BENIGN: nine Brute Force, four DDoS, ninety-two DoS and five Port Scan rows. Three additional Port Scan rows are predicted as DoS. These patterns show that the principal offline error burden is benign traffic being classified as attacks.

The mean saved winning confidence is approximately 0.98847 for correct predictions and 0.72097 for incorrect predictions. This association suggests that score-aware review could be useful, but it does not validate a threshold policy. Thresholds selected using this test set would contaminate its role as final evaluation data. Any change should be selected using validation data and then tested once on a separate untouched population.

## 4.6 ROC and precision–recall analysis
The saved CSV includes the winning confidence but not all five class probabilities. ROC and PR curves cannot be reconstructed correctly from that single score alone. The audit therefore regenerates the complete probability matrix from the saved model and all 24 test features, verifies label agreement, and stores the matrix with its runtime provenance. Fig. [[fig:roc]] and Fig. [[fig:pr]] are based on those regenerated scores.

[[FIG:roc|One-versus-rest ROC curves regenerated from the saved booster and test features using XGBoost 2.1.4. These are offline ranking results.]]

[[FIG:pr|One-versus-rest PR curves from regenerated probabilities. The black point shows the separate Brute Force multiclass argmax operating point.]]

Table [[tab:auc]] reports per-class ROC-AUC and average precision (AP). AP is calculated from the precision–recall ranking and is not the same as precision at the multiclass argmax decision. Brute Force can have high AP and still have low argmax precision because a thresholded one-versus-rest ranking answers a different question from choosing the greatest score among five classes. The black point in the PR plot makes this difference explicit rather than suggesting that the curve removes the observed false positives.

[[TABLE:auc]]

These curves describe performance on the saved test population. They do not establish calibrated probabilities, resistance to evasion, performance on newly collected hosts or detection of unseen classes. The close agreement between regenerated and saved macro AUC is an artifact-consistency result. It does not resolve upstream questions about how the original split and preprocessing interacted with dataset dependence.

## 4.7 Performance comparisons and baseline interpretation
A valid local comparison is an always-BENIGN baseline evaluated on the same saved test labels. It obtains approximately 83.2518% accuracy and 20% balanced accuracy, because it recalls the benign class and misses all four attack classes. Table [[tab:baseline]] contrasts this simple baseline with XGBoost. The comparison establishes that the model extracts information beyond the majority-class frequency on this evaluation set.

[[TABLE:baseline]]

No matched final test artifacts for Random Forest, support-vector classification or neural networks are verified in the repository. Introductory notebook prose mentioning several algorithms is not evidence of an executed final comparison. Similarly, published scores from different datasets cannot serve as a controlled baseline. A future comparison should use the same cleaned rows, split indices, feature contract, hyperparameter-selection budget and operating-point criteria for every candidate method.

## 4.8 Training provenance and notebook consistency
The raw local CSV row counts match the eight-file count table recorded early in the notebook. The final split and balancing outputs are consistent with the profile artifact’s selected population and saved test supports. However, earlier cleaning and selection cells retain contradictory outputs. One removal output starts again from 2,830,743 rows and reports remaining missing/infinite values; a later selection output contains only BENIGN and DDoS and gives 2,401,124 rows. Those states cannot be the immediate clean five-class input to the recorded final split.

This inconsistency is evidence of non-linear or partially stale notebook execution. It does not invalidate the independently checked saved test predictions, but it prevents certification of the notebook as a clean top-to-bottom reproduction of the original training run. The report accordingly describes training hyperparameters and recorded split counts as notebook evidence, while describing metric replay as independently executed evidence. No new model training is performed during the reporting task.

Preprocessing is written before the split, including median filling of invalid rate values. That design can expose information from future evaluation rows to a transformation estimated over the complete population. The potential effect is not measured here. The row-wise stratified split also does not enforce separation by source day, host or session. A stronger protocol would persist split membership and fit every learned preprocessing operation only on training data.

## 4.9 Resolution of the historical feature mismatch
The current feature engine computes timing in microseconds and rates per second. Contract tests check duration and inter-arrival units, payload accounting and schema order. The older guide’s warning that live seconds are sent directly into a microsecond-trained model is therefore not accurate for the audited code. This is a supported correction to the implementation account, not a claim that every source of live-to-training distribution shift has disappeared.

Remaining risks include the inferred historical flag semantics, first-packet duplication in length statistics, padding behavior, first-observed direction, FIN segmentation and differences among capture platforms. The pipeline applies a 120-second maximum age but retains a configurable inactivity rule. Retransmissions and partial captures can change packet counts and lengths even if units are correct. The packet simulations include a port-scan retransmission sensitivity test, reinforcing that small traffic-shape changes can affect predicted labels.

## 4.10 Saved end-to-end laboratory validation
The saved validation report records five sequential profile runs. Its total flows sum to 1,159, matching validation_detections.jsonl. Every record in that file identifies REAL ML and has demo_fallback false. The genuine class counts over all records are BENIGN 826, Brute Force 4, DDoS 190, DoS 24 and Port Scan 115. Those aggregate counts include closing tails and are not themselves profile-specific correctness counts.

To corroborate the report, the JSONL file is partitioned into consecutive blocks using the recorded totals 595, 9, 382, 50 and 123. Their time spans are sequential and separated. Selecting first_packet_flags equal to S within those blocks reproduces the reported opening-flow counts. Table [[tab:live]] gives exact reconstructed matches, and Fig. [[fig:live_counts]] compares their counts. The original ProfileWindow objects are not persisted; this reconciliation is therefore explicitly a reconstruction guided by the saved report, not an independent recovery of ground-truth windows.

[[TABLE:live]]

[[FIG:live_counts|Saved laboratory opening-flow counts, reconciled using consecutive JSONL blocks and the saved report’s profile totals. Matching is relative to the selected profile.]]

The Brute Force run contains four matching opening flows out of five, giving 80%, below the utility’s 90% rule. The saved report labels its final demonstration verdict fabricated. The underlying genuine detections remain valid observations; a fabricated final verdict cannot turn the failed profile criterion into a successful experiment. The other opening-flow matches are 298/298 BENIGN, 188/190 DDoS, 23/24 DoS and 115/119 Port Scan. These results demonstrate selected laboratory profile recognition under the recorded setup, with very limited Brute Force sample size.

A separate detections.jsonl contains 1,554 records, including eight session records and 219 per-flow fallback records. Its source strings include both historical fabricated labels and the current fetching label. It is deliberately excluded from pooled performance calculation. Records in that file may still preserve genuine fields, but display values must not be treated as classifier outputs. No packet-capture file is supplied to independently reconstruct the original live features or measure capture losses.

## 4.11 Executed tests and failure interpretation
The unrestricted loopback-capable audit run executes 202 tests in 28.078 seconds. It has 196 passes, six failures and no errors. The failing cases are listed in Table [[tab:failures]]. Several compare the expected explicit fabricated-result string with the current “Fetching RESULT” label. Dashboard-related failures additionally expose inconsistent recognition or presentation of fabricated verdicts. They are not reported as detector accuracy failures, but they directly affect trust in displayed results.

[[TABLE:failures]]

Passing tests establish useful local properties: feature-contract behavior, saved-model loading, representative class vectors, module handoffs and simulated packet-profile classification. They do not prove Windows capture privileges, Npcap driver operation or long-running stability on the target machine. The test named run_live wiring uses a mocked capture path. The report preserves these distinctions so that a green test for orchestration is not represented as a fresh real-time capture experiment.

## 4.12 Runtime observations and implementation costs
A single audit batch prediction for 251,812 rows takes 3.1602 seconds with the booster configured for four threads. Model loading and DMatrix construction occur before the timed interval. This is an offline inference observation on one host and one run. It is not a packet throughput benchmark, a confidence interval, or an estimate of the latency experienced by an individual live flow.

Live latency includes flow completion, feature computation, single-row DMatrix creation, prediction, callback processing and display refresh. Idle flows may wait for another packet or a flush before expiration is acted upon. The builder scans active flows during expiration, and completed results retain packet metadata. These implementation costs motivate future throughput, memory and packet-loss measurements. No unsupported packets-per-second or production-capacity claim is derived from the batch timing.

## 4.13 Threats to validity and supported interpretation
Internal validity is limited by stale notebook outputs, preprocessing before splitting, inferred compatibility semantics and absent original live packet captures. External validity is limited by the selected five classes, a historical dataset, controlled loopback traffic and no independently labelled deployment population. Construct validity is limited when a selected profile is used as the expected class: matching that label measures conformity to a laboratory stimulus, not necessarily detection of malicious intent.

The supported interpretation is that the repository implements a connected packet-to-flow classifier, reproduces the saved offline labels, and contains recorded laboratory evidence of several profile matches. It also retains substantial Brute Force precision limitations and presentation-source defects. Those qualifications are integral to the result. High aggregate offline metrics support continued engineering investigation; they do not establish a production-ready autonomous security system.

# 5 Summary and Conclusions
## 5.1 Summary of the investigation
The investigation traces the MLCN implementation from capture through classification and assesses its evidence at each boundary. The current source contains five integrated processing modules, a canonical 24-feature contract, a saved XGBoost multiclass model, local CIC flow data, a training notebook, laboratory generators, receiver services, launcher utilities and a receiver-aware Streamlit console. The report also documents the optional display fallback that can substitute synthetic values for presentation while retaining the genuine model result.

Independent replay confirms all 251,812 saved class predictions and the exact saved confusion matrix. Original diagrams document the architecture, while charts report verified class counts, scores and regenerated probability rankings. Existing live-validation records are reconciled with their summary using an explicitly stated method. The institutional document structure is preserved, with unknown student, guide and outcome-mapping details left for authorized completion.

## 5.2 Objectives achieved
Table [[tab:achievement]] summarizes achievement against the investigation objectives. The distinction between completed engineering work and incomplete deployment validation is maintained. A proposed Gemini explanation workflow is specified in enough detail to guide implementation, but it is not included among implemented or empirically validated contributions.

[[TABLE:achievement]]

## 5.3 Conclusions derived from the results
First, a usable classifier integration depends on an exact measurement contract. Current MLCN timing features use microseconds, rates use seconds, and payload and flag rules are explicitly defined. This repairs the historical timing mismatch described in the supplied guide. The unusual compatibility semantics remain important limitations when transferring to another extractor or retraining on corrected data.

Second, the saved offline model exhibits strong overall classification performance on its recorded test population: 99.4238% accuracy and 99.5568% balanced accuracy. These findings are independently reproduced from saved labels and verified by model replay. The aggregate result must be read alongside macro F1 of 0.93358 and Brute Force precision of 0.53138. The latter corresponds to 799 false positives among 1,705 Brute Force predictions.

Third, the available laboratory evidence supports selected profile recognition but has a narrower interpretation than general intrusion-detection accuracy. Brute Force matches only four of five opening flows in the saved validation run. Synthetic final verdicts and transformed display probabilities provide no evidence of improved detection. The test failures around their labelling show why provenance must be a visible, machine-checkable property of every reported result.

Fourth, the notebook is informative but not a fully certified reproducibility pipeline. It records splits, balancing, hyperparameters and training output, yet its earlier saved states are inconsistent. A repeatable training package must preserve preprocessing decisions, dataset identities, split membership and environment versions. The report’s successful inference replay addresses consistency of saved artifacts, not complete recreation of training history.

## 5.4 Contributions and limitations
The principal project contribution is a modular laboratory platform linking captured traffic to schema-validated multiclass inference. Its supporting tools allow bounded traffic generation, receiver observation and investigation of how flow shape affects classification. The present report adds a verified account of those mechanisms, corrected metric interpretation, reproducible result extraction and an explanation design that keeps factual evidence separate from generated language.

The main limitations are restricted class coverage, incomplete live provenance, weak rare-class precision, unresolved test failures in presentation behavior, possible flow-state concurrency and shutdown issues, and missing long-duration performance measurements. There is no implemented attribution engine, Gemini reporting service or incident database. There is also no controlled comparative benchmark establishing that XGBoost outperforms alternative models under an identical protocol.

## 5.5 Specific future scope
The first priority is trustworthy evidence handling. Demonstration fallback should be disabled in evaluation, its source should be unambiguous in every record type, and the six failing tests should be resolved through an explicit product decision. A new evidence sink should store feature values, schema/model hashes, capture context and completion reason alongside genuine predictions. These changes would make later error analysis and explanation grounding auditable.

The second priority is repeatable data preparation and evaluation. A clean training script should replace state-dependent notebook execution, fit imputation on training data, preserve source/session identifiers and create group-aware held-out sets. Raw-data hashes and extractor versions should be stored with every model. The Brute Force decision boundary should then be studied through additional representative benign and attack flows, validation-only threshold selection, calibration and comparisons with matched baselines.

The third priority is live-system measurement. Repeated authorized laboratory captures should vary operating system, interface, segmentation, retransmissions, background traffic and flow termination. Measurements should include packet loss, eligible-flow coverage, failure counts, memory growth and completion-to-prediction latency. An explicit stop channel, synchronized shared state and a timed expiration mechanism should be evaluated before extending the system to longer-running monitoring.

The final priority is the proposed explanation layer. A validated evidence adapter should precede any Gemini integration, with privacy minimization, versioned prompts and deterministic fallback behavior. SHAP may be evaluated as a separate feature-attribution component. Human assessment should compare factual correctness and usefulness against a simple template before claiming that generated narrative improves incident triage.
# 6 Appendix
## 6.1 Appendix I — Complete feature schema
Table [[tab:schema]] gives the ordered contract used by the runtime model. The order is part of the interface and must be preserved when exporting or constructing a vector. Types describe the numerical meaning; the inference array itself is float32. The formula column summarizes actual implementation behavior, including the exceptional flag mapping and length series. It is not a claim that every network-flow tool uses the same definitions.

[[TABLE:schema]]

For an illustrative arithmetic check, consider three timestamps at 0, 1,000 and 3,000 microseconds with payloads 10, 20 and 30 bytes, and directions forward, backward and forward. Duration is 3,000 microseconds and gaps are 1,000 and 2,000 microseconds. Their mean is 1,500 and sample standard deviation is approximately 707.107 microseconds. Flow Bytes/s is 20,000 and Flow Packets/s is 1,000. The overall length series is 10, 10, 20, 30, with mean 17.5 bytes. These are illustrative formula calculations, not captured experimental results.

The same example gives two forward packets, one backward packet and Down/Up Ratio equal to zero because floor(1/2) is zero. This result illustrates why interpreting that feature as a continuous proportion would be incorrect. A zero-duration case would instead use the contract’s fixed rate fills. A future independent extractor should be checked against examples of this kind and against real reference captures before it is permitted to supply model inputs.

## 6.2 Appendix II — Implementation inventory
Table [[tab:modules]] lists the audited implementation files by responsibility, including supporting packages beyond the five core modules. Entry-point and initializer files are small but important because they determine how command-line and package execution reach the same implementation. The full file-level Secure Hash Algorithm 256-bit (SHA-256) inventory is supplied in the report workspace. Virtual environments and version-control internals are excluded from scientific source claims.

[[TABLE:modules]]

The tests directory contains fixtures, a packet-profile simulation utility and fifteen test modules. Its test categories include common-schema generation, feature contracts, packet parsing, flow construction, detection, pipeline integration, traffic generation, local validation, launcher behavior, dashboard behavior and demonstration provenance. Assets contain four project images and the compact traffic-profile JSON. The images are contextual design artifacts; the JSON supplies reference statistics used by the generator. The top-level query file contains a short Npcap lookup token and has no verified executable role.

## 6.3 Appendix III — Configuration and operating modes
Table [[tab:config]] distinguishes standalone builder settings from integrated pipeline and launcher settings. This avoids mixing values from different entry points. Laboratory port filtering affects capture and callback display; eligibility still requires TCP or UDP and at least two packets. A source record should include the selected configuration whenever results from different runs are compared.

[[TABLE:config]]

The requirements file specifies Scapy at least 2.5 and below 3, XGBoost at least 2 and below 3, NumPy at least 1.20 and below 3, and Streamlit at least 1.37 and below 2. The training metadata’s XGBoost 3.4.1 lies outside that declared runtime range. The audit successfully loads the model with 2.1.4 and verifies its predictions, but a future release should pin and test a consistent development and deployment environment rather than leave this discrepancy implicit.

## 6.4 Appendix IV — Reproducibility instructions
The report workspace contains the audit script, source inventory, metric results, probability matrix, plotting script, manuscript and document-generation script. Reproduction of the report’s metric checks begins from the unmodified model and saved prediction CSV. The audit computes labels and metrics without fitting a new model. Its hash inventory provides a way to determine whether source artifacts have changed since the report was generated.

Table [[tab:commands]] gives concise commands and their intended roles. Commands for capture are instructions for an authorized laboratory environment and are not a record of execution during this audit. Interface names are platform-specific and must be selected from actual discovery output. The Windows launcher is intentionally platform-specific; the macOS audit host cannot certify Npcap operation by running ordinary unit tests.

[[TABLE:commands]]

A complete future training reproduction should first repair notebook state dependencies, replace machine-specific paths with parameters, persist exact source ordering and split membership, and pin library versions. It should then reconstruct the selected class population, fit preprocessing only on the training partition, perform the recorded undersampling and weighting, and train with validation-only early stopping. New results should be stored under a new model identity rather than overwrite the current evidence silently.

The report-generation environment is independent from the application environment. It adds document and plotting libraries solely under reports/workspace. The original application modules and model artifacts are not edited. Test execution uses temporary test directories where the suite requests them and disables bytecode generation for the audit run. Any reproduction should retain failed-test output as well as successful checks, because presentation failures affect the interpretation of results.

## 6.5 Appendix V — Proposed explanation contract
Table [[tab:xai_contract]] defines the proposed explanation envelope and response. Names in this table are design suggestions, not an implemented public API. The required source of classification fields is the genuine detector output. The actual JSONL format must be extended or bypassed through an in-memory adapter to include all feature evidence. A missing feature block cannot be reconstructed from probabilities alone.

[[TABLE:xai_contract]]

The response validator should verify that every evidence reference resolves, all repeated numerical values agree within an explicit tolerance, and no generated output changes the original prediction. Explanatory language should distinguish an observed statistic from an attribution and distinguish both from a causal claim about an incident. A synthetic record, invalid schema, absent provenance or privacy-policy failure should produce a factual refusal or deterministic summary rather than a plausible narrative.

## 6.6 Appendix VI — Supplementary evidence and traceability
Table [[tab:rawfiles]] records the local raw CSV file sizes in rows, as counted during this audit. The filenames are retained to allow exact correspondence with the workspace. Their sum is 2,830,743. The source population in the profile artifact is smaller because it describes a selected and cleaned task population. The notebook’s inconsistent intermediate outputs prevent treating that entire reduction as a freshly certified preprocessing lineage.

[[TABLE:rawfiles]]

Table [[tab:hashes]] provides selected artifact hashes for traceability. Full hashes and the complete inventory remain available in the machine-readable workspace file. Model, schema and evaluation artifacts should travel together; changing one without a new identity can invalidate a seemingly reproducible prediction. The audit date identifies the local inspection, while the institutional academic-year label remains the supplied template’s 2025–26.

[[TABLE:hashes]]

# 7 References / Literature Cited
## 7.1 Bibliography in order of first citation
The following entries are numbered in first-citation order. Online source verification was performed on 21 October 2026. Repository-derived facts cite exact artifact paths in the relevant chapters and appendices; the file inventory records their local provenance. Patent entries identify publications and technical relevance only. They do not assert project novelty or a legal clearance.

[[REFERENCES]]

## 7.2 Related-patent verification scope
The related-patent review in Section 2.8 verifies two publication records and discusses their relevance to monitored-traffic compatibility and adaptive representations. The checked database is Google Patents, with publication identifiers US12143406B1 and US20220021695A1. Search coverage is intentionally limited to directly relevant accessible records. No exhaustive family search, prosecution-history review or jurisdiction-specific claim analysis is represented as completed.

#P List of Publications
The repository contains no verified publication by the candidate or project team. Table [[tab:publications]] records that status in the institutional format. It should be replaced only with an authenticated publication entry, including its actual authors, venue, date and indexing information.

[[TABLE:publications]]
