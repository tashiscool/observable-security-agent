# Observable Security Agent — BuildLab pitch

This document is for **judges and competition reviewers**. The technical product description, API, and workflows live in [README.md](README.md).

---

## Elevator pitch

Security and compliance teams are buried in scanner output, log schemas, and narrative reports that **do not connect**. Meanwhile, generic LLMs happily draft “remediation plans” with **no proof** that the underlying controls are actually satisfied. **Observable Security Agent** is a different thing: a **deterministic evidence-correlation and assessment-evaluation layer** that answers, for each asset, event, and finding, whether the **proof chain** is demonstrable—inventory, scanner scope, centralized logging, alerting, change linkage, exploitation review when it matters, and POA&M when gaps remain.

The system **does not invent evidence**. Gaps are **FAIL/PARTIAL** with explicit narratives about what was missing. Optional AI explanation is **grounded**: it consumes the same structured artifacts (eval results, graph, POA&M) and carries an **evidence contract** footer so reviewers see what was—and was not—allowed into the answer.

**Bounded autonomy** matters for real operations. The `run-agent` playbook runs observe → plan → act → explain with **policy decisions on every step**, a fixed blocked-action catalog, and **no silent execution** of cloud mutation or ticket creation. This is autonomy with guardrails, not an unconstrained agent with API keys.

---

## Why this solves real compliance problems

| Pain | How this project addresses it |
| --- | --- |
| “We passed the scanner” ≠ defensible ATO narrative | Evaluations tie **controls and (when enabled) FedRAMP 20x KSI-style** rolls ups to **explicit evidence**, not tool marketing language. |
| Reports drift from machine-readable truth | **Reconciliation** and validation scripts check that human-facing outputs align with the **same** JSON package the machine validated. |
| LLM hallucinations in audits | Explain paths are **artifact-bounded**; deterministic modes run with **no** model; LLM paths are optional and wired to fail closed into deterministic explanations. |
| Agentic risk | Dedicated evals and **threat-hunt** outputs cite **evidence_refs** into agent tool calls, memory, policy violations, and identities—no orphan narratives. |

---

## How We Solve the 3PAO Assessment Problem End-to-End

To solve the compliance and assessment problem whole, we built a solution that seamlessly connects raw ecosystem reality with high-level 3PAO (Third-Party Assessment Organization) evaluation standards.

- **Leveraging Existing Ecosystems & Automations:** We don't reinvent the wheel. The agent natively ingests raw evidence from the systems already running in your environment—**AWS CloudTrail** for control-plane events, OS-level logs via **Wazuh**, centralized SIEM data from **Splunk**, and cloud metrics from **CloudWatch**. We map these through OCSF and Prowler adapters to build a unified evidence graph.
- **Solving the 3PAO Problem Whole:** 3PAOs need to trace a control from the FedRAMP narrative down to the raw JSON log. Our deterministic engine maps evidence directly to FedRAMP 20x KSIs (Key Security Indicators), ensuring there is zero gap between technical reality and the final audit package.
- **Evaluating Ticketing Solutions:** Compliance isn't just scanners; it's manual tracker sheets. We ingest **Smartsheet, Jira, and ServiceNow** exports and use the agent to semantically map unstructured ticket gaps into machine-readable POA&M findings, bridging the gap between DevOps ITIL ticketing and ATO packages.
- **Validating the "Reasonableness" Test:** Auditors constantly perform a "reasonableness" test on evidence. Our agent performs this automatically against the evidence graph—evaluating log maturity, inventory coverage, and correlation completeness—flagging partial or insufficient evidence *before* the 3PAO ever sees it.
- **Leveraging the Power of AI (Safely):** We unleash LLM capabilities where they shine—parsing unstructured ticket narratives, explaining complex failure graphs, and drafting auditor responses—but strictly bound them within a deterministic "Evidence Contract" so they can never hallucinate a passing control.

For the complete reference-to-capability map, see [Competition Auditability Capability Inventory](docs/competition_auditability_feature_inventory.md). It traces 72 checked-in reference samples from 12 upstream projects into the implemented ingestion, evidence graph, 3PAO reasonableness, ConMon, FedRAMP 20x, reporting, and guardrail features. Remaining reference-driven work is tracked in [Reference-Driven Gap Implementation Plan](docs/reference_driven_gap_implementation_plan.md).

---

## Proof: exhaustive verification (GovCloud)

An end-to-end harness (`scripts/verify_all_features.sh`) was executed with **live AWS GovCloud** credentials and **`REGION=us-gov-west-1`**. It exercises, among other things:

- Full **pytest** suite  
- Every major **`agent.py`** path (fixtures, AWS-shaped raw dirs, imports, 20x package, reconcile)  
- **FastAPI** `/api/health` and `/api/explain`  
- Static **Security Evidence Explorer** (`web/`) HTTP contract  
- **Prowler** and **OCSF** importers  
- **Cypher export** (Neo4j-oriented graph export)  
- **CSV → creds → STS → live `collect_aws_evidence` → `assess` → `validate_outputs` → `threat-hunt` on live raw**

**Outcome (representative run):**

- **Pytest:**  **1025 passed** (current full offline suite, local hardening run)  
- **Feature harness:** **32 × PASS**, **0 × SKIP** (live AWS path enabled; no gates skipped)  
- **GovCloud:** STS caller identity succeeded; live collection and assessment **VALIDATION PASSED**  

To reproduce (use your own access key CSV; do not commit credentials):

```bash
cd observable-security-agent
pip install -r requirements.txt
pip install -e '.[api]'   # FastAPI + uvicorn for harness API checks

make verify-all-features OS_AGENT_CSV=/path/to/YOUR_accessKeys.csv REGION=us-gov-west-1
# Also works: export OS_AGENT_CSV=... REGION=... && make verify-all-features
# Or:        env OS_AGENT_CSV=... REGION=... bash scripts/verify_all_features.sh
```

Detailed console capture from the proof run is retained locally as `/tmp/verify_all_features_run.log` (not shipped in-repo).

---

## Live AI "Reasonableness" Test Demonstration

To prove to the judges that the "reasonableness" evaluation is fully integrated with live LLM reasoning (via AWS Bedrock or Ollama), you can run our holistic Live AI integration demo. This spins up a local proxy, routes the deterministic AI reasoning engine to Bedrock, and prints the bounded explanation for a reasonableness failure (like CM-8 inventory gaps).

```bash
# Requires litellm installed locally. Use your own CSV; do not commit credentials.
make demo-live-ai CSV_FILE=/path/to/accessKeys.csv
```

---

## Golden Path: Agentic Assurance Package Demo

For judges who want one complete, credential-free walkthrough, the golden path demo runs the full compliance assurance pipeline on fixture data:

```bash
cd observable-security-agent
python agent.py golden-path-demo --output-dir build/assurance-package-demo
```

It produces `assurance-package.json`, Markdown reports, metrics, eval outputs, and an agent run log. The fixture covers AWS ECR/container vulnerability findings, CloudTrail audit logging, IAM/access evidence, cloud configuration evidence, stale evidence, missing evidence, human-reviewed false positive disposition, human-reviewed risk acceptance, and an unresolved HIGH mapped to `RA-5` / `SI-2`.

The screenshots in this section are actual browser captures from the local Security Evidence Explorer UI. The capture script first regenerates the golden-path artifacts, then opens the web UI and captures the panels that expose those artifacts.

**End-to-end pipeline**  
![Golden path pipeline](docs/competition/feature_golden_path_pipeline.png)

**Machine-readable assurance package manifest**  
![Assurance package manifest](docs/competition/feature_assurance_package_manifest.png)

**Evidence and normalized findings**  
![Assurance evidence and findings](docs/competition/feature_assurance_evidence_findings.png)

**Human review preservation**  
![Human review decisions](docs/competition/feature_human_review_decisions.png)

**Metrics and offline evals**  
![Metrics and evals](docs/competition/feature_metrics_evals.png)

**Human-readable reports and agent run log**  
![Reports and run log](docs/competition/feature_reports_run_log.png)

To regenerate these browser PNGs from real local outputs:

```bash
python scripts/serve_web.py --port 8080
python scripts/capture_competition_screenshots.py
```

---

## Security Evidence Explorer (visual)

Headless capture of the static explorer (sample data) demonstrating continuous monitoring (ConMon) and automated evaluation scenarios:

The screenshots below are actual browser captures from the local Security Evidence Explorer UI. They were regenerated by serving the app and running the Playwright capture scripts:

```bash
# Terminal A
python scripts/serve_web.py --port 8080

# Terminal B
python scripts/capture_competition_screenshots.py
python scripts/capture_conmon_19_screenshots.py
```

### Executive Overview
![Security Evidence Explorer — main UI](docs/competition/explorer-main.png)

### Continuous Monitoring (ConMon) Verification

**CM-8 (Inventory Reconciliation)**  
Validates that new assets are automatically discovered and reconciled with vulnerability scanning coverage.
![CM-8 Inventory](docs/competition/conmon_cm8_inventory_reconciliation.png)

**RA-5 (Vulnerability Scanning)**  
Proves that OS, infrastructure, and web applications are authenticated and scanned successfully.
![RA-5 Vuln Scanning](docs/competition/conmon_ra5_vulnerability_scanning.png)

**SI-4 (System Monitoring)**  
Shows the agent validating alert routing and centralized logging for real-time monitoring.
![SI-4 System Monitoring](docs/competition/conmon_si4_system_monitoring.png)

**CA-5 (POA&M Updates)**  
Automated POA&M matrix generation mapping residual risks to failed evaluations and missing evidence.
![CA-5 POA&M Updates](docs/competition/conmon_ca5_poam_updates.png)

### Modern Threat Capabilities

**Agentic Risk & Shadow AI Monitoring**  
The agent bounds execution and highlights advanced threats such as insider risk or unauthorized AI usage.
![Agentic Threat Hunt](docs/competition/conmon_threat_hunt_agentic_risk.png)

**Replay locally for video or deeper UI review:**

```bash
# Terminal A — static Explorer (serves repo root; default http://127.0.0.1:8080/web/index.html)
python3 scripts/serve_web.py

# Terminal B — optional explain API for live AI explanation tab against your outputs
python3 -m uvicorn api.server:app --host 127.0.0.1 --port 8081
```

Then open `http://127.0.0.1:8080/web/index.html` in a browser. For a judge-ready **screen recording**, drop `buildlab-walkthrough.mp4` (or similar) alongside the PNG under `docs/competition/` and link it here.

---

## 19-Point Annual ConMon Checklist (Procedural Reviews)

The **DevOps Ticketing Integration (Smartsheet/Jira)** is purpose-built to automate procedural and policy reviews (Access Control, Contingency Planning, Media Protection, etc.). Here is explicit visual proof of all **19 ConMon checklist items** ingested directly from the DevOps tracker and evaluated for evidence gaps.

- **Tracker Import (19 Policies loaded)**: ![Tracker Import](docs/competition/conmon_19_tracker_import.png)
- **Automated Evidence Gap Evaluation**: ![Tracker Gaps](docs/competition/conmon_19_evidence_gaps.png)

---

## Comprehensive Feature Gallery

To prove the depth and complete implementation of the `observable-security-agent`, here is a complete visual walkthrough of the 20+ feature panels available in the local Evidence Explorer.

### Core Ecosystem & Graph
- **Evidence Graph**: ![Evidence Graph](docs/competition/feature_evidence_graph.png)
- **Correlation Timelines**: ![Correlation Timelines](docs/competition/feature_correlation_timelines.png)
- **Control View**: ![Control View](docs/competition/feature_control_view.png)
- **Asset View**: ![Asset View](docs/competition/feature_asset_view.png)

### Agent Capabilities
- **Instrumentation Rules**: ![Instrumentation](docs/competition/feature_instrumentation.png)
- **Secure Agent Architecture**: ![Secure Agent](docs/competition/feature_secure_agent_architecture.png)
- **Auditor Questions**: ![Auditor Questions](docs/competition/feature_auditor_questions.png)
- **AI Explain Engine**: ![AI Explain](docs/competition/feature_ai_explain.png)

### FedRAMP 20x Automated Packaging
- **20x Dashboard**: ![20x Dashboard](docs/competition/feature_20x_dashboard.png)
- **KSI Explorer**: ![KSI Explorer](docs/competition/feature_20x_ksi_explorer.png)
- **Crosswalk View (Rev4/Rev5)**: ![Crosswalk View](docs/competition/feature_20x_crosswalk.png)
- **Findings Generation**: ![Findings View](docs/competition/feature_20x_findings.png)
- **Deep Reconciliation**: ![Reconciliation](docs/competition/feature_20x_reconciliation.png)

### DevOps Ticketing & Tracker Ingest (Smartsheet/Jira)
- **Tracker Import**: ![Tracker Import](docs/competition/feature_tracker_import.png)
- **Evidence Gaps Evaluated**: ![Evidence Gaps](docs/competition/feature_tracker_evidence_gaps.png)
- **Agent Run Trace**: ![Agent Run Trace](docs/competition/feature_tracker_agent_run_trace.png)
- **LLM Reasoning Traces**: ![LLM Reasoning](docs/competition/feature_tracker_llm_reasoning.png)
- **Virtual 3PAO Remediation Evaluation**: ![3PAO Remediation](docs/competition/feature_tracker_3pao_remediation.png)
- **Tracker-Derived 20x Package**: ![Tracker Package](docs/competition/feature_tracker_20x_package.png)
- **Complete Derivation Trace**: ![Derivation Trace](docs/competition/feature_tracker_derivation_trace.png)

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
