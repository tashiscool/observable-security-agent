# Observable Security Agent

## Positioning

**Observable Security Agent** is an **evidence-correlation and assessment-evaluation layer**. It sits above scanners, asset graphs, and log schemas; it does not replace them.

**This is not** a CSPM scanner, **not** merely a FedRAMP Rev4/Rev5 control crosswalk, and **not** a report generator that stands alone without a provable artifact chain. Upstream scanners, graphs, and crosswalks may **supply** normalized inputs; they are not the product definition.

### Evidence chain the system must prove

End-to-end traceability (FedRAMP 20x–oriented packaging when enabled):

**Rev4/Rev5 control evidence → FedRAMP 20x KSI capability → validation criterion → evidence source → machine-readable result → finding → POA&M item → assessor / executive / AO explanation → reconciliation** showing human-facing outputs match the machine-readable package.

The engine **does not invent evidence**. Absent or insufficient proof is recorded as a **gap** (FAIL/PARTIAL)—a first-class outcome—not as silent pass or narrative filler.

For a given **asset**, **event**, or **finding**, the agent answers one controlling question:

> **Can we prove** it is **in inventory**, **in scanner scope**, **centrally logged**, **covered by an alert**, **linked to a ticket**, **reviewed for exploitation** if High/Critical, and **tracked in POA&M** if unresolved?

Each link is evaluated against loaded evidence. Missing proof is a **gap** (FAIL/PARTIAL), not treated as if the control were satisfied. Everything else—normalization details, the evidence graph shape, auditor prompts, instrumentation query templates, merge-friendly POA&M CSV—is **secondary**: it supports answering that question and packaging gaps for assessors.

### Every failed or partial result must explain

1. **What was evaluated** (eval / KSI / criterion scope).  
2. **What evidence was used** (explicit artifact refs and hashes where configured).  
3. **What evidence was missing** (concrete gaps, not assumed coverage).  
4. **Which control / KSI is impacted** (Rev4/Rev5 and 20x KSI linkage from config).  
5. **What artifact would close the gap** (collectible evidence or configuration, per policy).  
6. **Whether POA&M or formal risk acceptance is required** (per POA&M / risk policy—not a generic “fix it” note).

## What it does

The agent consumes normalized evidence (fixtures or cloud-shaped exports), runs a fixed evaluation pipeline, and writes outputs. **Core** work is the proof chain above (inventory, RA-5 scope, AU-style central logging, SI-4 alerting, CM-3/SI-2 ticket linkage, RA-5(8) exploitation review where applicable, CA-5 POA&M when gaps remain).

### Cloud evidence vs. agent security evidence

Two distinct evidence classes show up in the bundle—judges and operators should see both:

| **Cloud evidence** (workload / account) | **Agent security evidence** (how we know the assessment is trustworthy) |
|----------------------------------------|---------------------------------------------------------------------------|
| Declared inventory, discovered assets, scanner targets & findings, cloud events, log-source samples, alert rules, tickets, POA&M seeds—everything normalized into `AssessmentBundle` and the evidence graph | `eval_results.json` with FAIL/PARTIAL narrative fields, `validate_outputs.py` gates, optional **checksums** on package artifacts, **reconciliation** between Markdown reports and machine JSON, schema validation (`fedramp20x-package.schema.json`), and **AI explain** inputs limited to those files (no invented facts) |
| Produced by **your** exports (`fixtures/`, or `collect-aws` → `assess-aws`) | Produced by **this** pipeline (`assess`, `build-20x-package`, `validate-20x-package`, `reconcile-20x`) so reviewers can replay and diff results |

**This repository does not claim or ship proprietary third-party assessment frameworks** (e.g. vendor-exclusive ATO worksheet products). Configuration uses **public control families** (NIST 800-53 Rev language), **FedRAMP-style** KSI packaging conventions, and project-owned YAML/CSV under `config/` and `mappings/`.

**Supporting** automation and narratives include:

- **Normalizes** inputs into a canonical `AssessmentBundle` (events, assets, findings, targets, log sources, alert rules, tickets, optional POA&M seeds).
- **Builds an evidence graph** linking the primary signal to the same artifacts the proof chain uses.
- **Cross-domain correlation** checks that correlated risky events meet the same chain expectations.
- **Human and machine reports** (`correlation_report.md`, `eval_results.json`, gap matrix) and **POA&M rows** for failed/partial evals.
- **Auditor questions** and **instrumentation plan** templates (Splunk, Sentinel, GCP, AWS-oriented) to close gaps—convenience for operators, not the definition of pass/fail.

### Product layers (three tiers)

1. **Evidence correlation layer (existing)** — assets, events, scanner findings, logs, alerts, tickets, POA&M seeds, evidence graph, and deterministic **control evaluations** (`assess` → `output/`).
2. **FedRAMP 20x KSI package layer (new)** — config-driven **KSI catalog**, Rev4→Rev5→20x-style KSI **crosswalks** (mapping inputs only), **evidence source registry**, **KSI validation rollups**, structured **findings**, **POA&M items**, **evidence links**, **schema-valid** `fedramp20x-package.json`, and a **reconciliation** record. System-specific naming stays in **`config/`** and **`mappings/`**; `fedramp20x/` code stays generic.
3. **Human / AI explanation layer (existing + extended)** — assessor / executive / AO **Markdown** reports generated from the **same package snapshot** as the JSON; **web/** explorer; optional **`api/`** explain endpoint.

After a successful `assess`, build the 20x package:

```bash
python agent.py build-20x-package \
  --assessment-output output \
  --config config \
  --package-output evidence/package
```

The command validates the result against **`schemas/fedramp20x-package.schema.json`**. Human reports under `evidence/package/reports/` cite the same counts and (when enabled) the **SHA-256** of the pre-reconciliation machine body so reviewers can align narratives to the JSON.

## Why OCSF, Prowler, and Cartography are inputs—not replacements

These systems solve different problems and sit **below** this project’s layer:

| Source / standard | Role |
| --- | --- |
| **OCSF** | A **schema vocabulary** for normalizing security telemetry and findings. Useful as a *lingua franca* for events and objects—not a program-level evidence or POA&M narrative. |
| **Prowler** | A **cloud security scanner** that produces findings and configuration evidence. It is a **findings and posture source**, not a cross-control correlation or audit-package generator. |
| **Cartography** | An **asset graph / topology** source. It enriches **what exists and how it connects**; it does not by itself prove logging, alerting, change linkage, or exploitation-review discipline. |

**Observable Security Agent** is the **evidence-correlation and assessment-evaluation layer** above those inputs: for each asset/event/finding in scope, it asks whether the **proof chain** (inventory → scanner scope → central logs → alerts → tickets → exploitation review when High/Critical → POA&M when unresolved) is demonstrable from evidence—using deterministic rules, not whether a single upstream tool “passed.”

## Quickstart

```bash
cd observable-security-agent   # or your clone path

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# Run the bundled public-admin / vulnerability demo (no AWS credentials)
python agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event

# Fail fast if the output directory is not a complete evidence package
python scripts/validate_outputs.py --output-dir output
```

### Full acceptance gate (`make all` / `make test`)

From `observable-security-agent/`, **`make all`** runs the **cloud-style** fixture (`scenario_public_admin_vuln_event`) through `validate_outputs`, **FedRAMP 20x** package build, schema validation, report regeneration, and reconciliation, then runs the **bounded autonomous loop** (`run-agent`) on the **agentic-risk** fixture (default **`output_agentic/`** — see `Makefile`). That loop is evidence-only: evals, drafts, package validation, and trace files—**not** auto-remediation or external ticket creation. Finally **`make demo`** writes **`output/demo_walkthrough.md`** for BuildLab / sponsor walkthroughs. **`make test`** runs the full pytest suite. **`make verify-demo`** runs **`scripts/verify_demo.sh`**: pytest, **`make all`**, BuildLab readiness, fixture bundle (bounded loop, cloud assess, threat hunt, 20x validate, deterministic explain), **`assess --provider aws`** against the **fixture-shaped** evidence directory (same path CI uses), and a **best-effort** live **`collect_aws_evidence --fixture-compatible`** + **`assess-aws`** on the **per-region** directory that contains `manifest.json` (companion **`cloud_events.json`** is written there as well as the collect root so assess can load events). For the broadest end-to-end smoke (every CLI subcommand, every helper script, **FastAPI** explain server in-process, static **web** server fetch checks, all three fixture scenarios, optional live AWS), run **`make verify-all-features`** (set **`OS_AGENT_CSV=/path/to/accessKeys.csv`** to also exercise CSV bootstrap → run-with-creds validate → live collect → assess-aws → threat-hunt aws). To bootstrap session keys from an access-key CSV and then run the same verification: **`make aws-bootstrap-verify CSV_FILE=/path/to/accessKeys.csv`** (optional **`REGION=us-gov-west-1`**), or set **`OS_AGENT_CREDS_JSON=/path/to/session/creds.json`** before **`make verify-demo`** to load STS credentials without printing them. Underlying bootstrap: from **`security-infra`** root, **`bash infrastructure/packer/bootstrap-creds-json-from-csv.sh --csv-file …`** (do not commit **`creds.json`**).

### Minimal winning demo

After install (`pip install -r requirements.txt`), from this package directory:

```bash
python agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event
python scripts/validate_outputs.py --output-dir output
```

`validate_outputs.py` checks the same files the agent writes and enforces the **FAIL/PARTIAL narrative contract** on `eval_results.json` (evidence used, gaps, controls or KSI links, remediation actions, and `remediation_disposition` for POA&M vs risk acceptance—see `core/failure_narrative_contract.py`). A complete evidence package includes:

| File under `output/` |
| --- |
| `evidence_graph.json` |
| `eval_results.json` |
| `correlation_report.md` |
| `auditor_questions.md` |
| `instrumentation_plan.md` |
| `poam.csv` |
| `evidence_gap_matrix.csv` |
| `assessment_summary.json` |

`correlations.json` is also written under `output/` when the correlation eval runs; the explorer loads it when present.

### Security Evidence Explorer (browser)

The **Security Evidence Explorer** is a plain **HTML / CSS / vanilla JavaScript** UI under `web/`. It **does not recompute** evaluations: it loads the structured artifacts and supports **derivation trace** views, control/asset/POA&M/instrumentation/auditor panels, and an **AI explain** area that calls a small optional API or falls back to **copyable grounded prompts**.

```bash
# After the minimal winning demo (writes output/)
python scripts/serve_web.py
```

Open **http://127.0.0.1:8080/web/index.html** (URL printed by the script). The UI tries **`../output/`** first (relative to `web/index.html`), then **`web/sample-data/`** so the repo ships a static fallback.

Optional **FastAPI** explain service (port **8081** by default in examples):

```bash
pip install -e ".[api]"
export AI_API_BASE="https://api.openai.com/v1"   # or your OpenAI-compatible endpoint
export AI_API_KEY="..."                          # optional; omit for deterministic responses only
export AI_MODEL="gpt-4o-mini"
uvicorn api.server:app --host 127.0.0.1 --port 8081
```

The browser panel posts to `http://127.0.0.1:8081/api/explain`. If the server is down or the key is missing, the UI still builds a **strict, copyable prompt** (no invented evidence).

**BuildLab line:** The Python engine produces the evidence graph and eval results; the browser renders each finding as an explorable evidence chain; the AI layer explains conclusions from the **provided artifacts only** and traces derivation from those files. For **AI Security Agent BuildLab / AgentLab** time blocks, submission checklist, and CSV→`/tmp`→`run-with-creds` testing, see **`docs/buildlab_agentlab_runbook.md`**.

Other useful commands:

```bash
python agent.py report --input output/eval_results.json --output-dir output
python agent.py list-evals
python agent.py validate --output-dir output
```

## AWS collection

Collect read-only AWS API evidence with boto3. Raw JSON is written under `raw/aws/{account_id}/{region}/` (identity, compute, networking, storage, logging, etc.). Use a profile and region as appropriate:

```bash
python scripts/collect_aws_evidence.py \
  --profile myprofile \
  --region us-east-1 \
  --output-dir raw
```

Optional: `--fixture-compatible` writes companion files (`discovered_assets.json`, `cloud_events.json`, and related stubs) beside `raw/` for a layout closer to fixtures; enrich events from authoritative CloudTrail exports before relying on them for a full assessment.

## AWS assessment

Point the agent at a directory whose **on-disk layout matches the canonical evidence files** (same filenames as under `fixtures/scenario_public_admin_vuln_event/`). You can override individual files (for example, a curated `declared_inventory.csv`) without replacing the whole tree:

```bash
python agent.py assess \
  --provider aws \
  --raw-evidence-dir raw/aws/ACCOUNT/REGION \
  --declared-inventory fixtures/scenario_public_admin_vuln_event/declared_inventory.csv
```

(`--evidence-dir` is accepted as a deprecated alias for `--raw-evidence-dir`.)

For a scripted wrapper that expects a single evidence root, see `scripts/run_aws_assessment.py`.

## Demo walkthrough

Use the **minimal winning demo** commands above so `validate_outputs.py` prints `VALIDATION PASSED`.

1. **Review** the evaluation lines in the terminal (PASS / FAIL / PARTIAL / OPEN per eval).
2. **Read** `output/correlation_report.md` — executive-style correlation and remediation framing.
3. **Read** `output/auditor_questions.md` — control-family questions tied to evidence gaps.
4. **Read** `output/instrumentation_plan.md` — Splunk, Sentinel, GCP, and AWS-oriented instrumentation blocks.
5. **Read** `output/poam.csv` — POA&M-style rows for gaps (including auto-generated rows where applicable).
6. **Inspect** machine-readable outputs: `output/eval_results.json`, `output/evidence_graph.json`, `output/evidence_gap_matrix.csv`, `output/assessment_summary.json`.

## Limitations

- **Initial scope** is the **AWS-shaped evidence path** plus the **fixture provider**. Other clouds are not first-class yet.
- This tool **does not replace auditor judgment**; it structures questions, gaps, and suggested evidence—it does not sign an ATO or waive risk.
- The agent **does not invent evidence**. Missing or weak evidence surfaces as **gaps**, failed or partial evaluations, and POA&M / auditor prompts—not as fabricated logs or tickets.

## Azure and GCP (future adapters)

**Planned:** dedicated providers (for example `providers/azure.py`, `providers/gcp.py`) that turn Azure Activity / Monitor and GCP Cloud Audit / SCC exports into the same **canonical** `AssessmentBundle` + on-disk evidence layout used today, so **the same eval modules** run without change.

**Today:**

- **Normalization:** `core/normalizer.py` only routes on `_format` / `event_type`; AWS CloudTrail–shaped rows are handled in `providers/aws.py`, and minimal **Azure / GCP audit-shaped** rows are handled in `providers/azure_gcp_normalizers.py` (no cloud SDKs). Fixture `cloud_events.json` can set `_primary` on `azure_activity` or `gcp_audit` rows—see `tests/test_vendor_neutral_architecture.py`.
- **Instrumentation:** `instrumentation_plan.md` always includes **Splunk**, **Azure Sentinel**, **GCP Cloud Logging**, and **AWS CloudTrail / EventBridge** sections where the plan is generated.
- **Collection:** only `scripts/collect_aws_evidence.py` ships for live API pull; Azure/GCP collection scripts are **not** in this repo yet—use curated exports or extend the provider layer following the AWS + fixture patterns.

## Testing

```bash
pip install -e ".[dev]"
pytest
python scripts/validate_outputs.py --output-dir output
```

The second command assumes you have already produced a complete `output/` directory (for example by running the fixture assessment first). In CI, point `--output-dir` at a temp directory produced by `agent.py assess` in a prior step.

Install `pip install -e ".[api]"` as well to run the FastAPI health import test (`tests/test_api_explain.py`); without it, one test is skipped and deterministic explain tests still run.

## Repository layout (short)

| Path | Purpose |
| --- | --- |
| `agent.py` | CLI: `assess`, `report`, `list-evals`, `validate`, **`build-20x-package`** |
| `config/` | System boundary, KSI catalog, evidence registry, crosswalk hints, validation/reporting policy (YAML) |
| `mappings/` | Rev4/Rev5/20x KSI CSV crosswalks and evidence/report maps |
| `schemas/` | JSON Schema for `fedramp20x-package.json` and component types |
| `fedramp20x/` | Package builder, KSI rollup, reconciliation, schema validation |
| `reports/` | (Generated under `--package-output`) `assessor/`, `executive/`, `agency-ao/`, `machine-readable/` |
| `core/` | Provider-neutral models, normalizer router, evaluator, evidence graph, reports, POA&M, output validation |
| `providers/` | Fixture + AWS loaders; `aws_evidence_raw.py` (boto3 collection); `azure_gcp_normalizers.py` (audit-shaped JSON) |
| `evals/` | One module per evaluation |
| `instrumentation/` | Platform query templates |
| `fixtures/` | Scenario data (e.g. `scenario_public_admin_vuln_event`) |
| `scripts/` | AWS collection, assessment helper, `validate_outputs.py`, `serve_web.py` |
| `web/` | **Security Evidence Explorer** (static UI + `sample-data/` snapshot) |
| `api/` | Optional FastAPI `/api/explain` with deterministic fallback |
| `reference_samples/` | Small upstream **examples only** (Prowler, Cartography, ElectricEye, AuditKit, OCSF)—see `manifest.json`; **not** vendored and **not** imported at runtime |
| `docs/` | Design notes (e.g. `reference_samples_index.md`) |
| `tests/` | Pytest suite |

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).  
Upstream excerpts under `reference_samples/` remain under their respective licenses (see `reference_samples/manifest.json` and `reference_samples/licenses/`).
