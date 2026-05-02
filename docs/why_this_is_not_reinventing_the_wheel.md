# Reference-backed build justification

## How we use cloned reference projects (do not reinvent)

We **study** full trees under `reference/` (gitignored) and ship **small excerpts** under `reference_samples/` with provenance in `reference_samples/manifest.json`. **Runtime code must not import** `reference/` or `reference_samples/` (see `scripts/audit_reference_reuse.py` and `scripts/validate_everything.py`).

| Reference stack | Use **this** way in our product |
| --------------- | ------------------------------- |
| **Prowler / CloudSploit** | **Scanner finding inputs** — adapters only (`providers/prowler.py`, `providers/cloudsploit.py`). |
| **CloudGraph / Fix Inventory / Cartography** | **Graph and asset-relationship references** — vocabulary and ideas for `core/evidence_graph.py` (our nodes/edges), not their sync engines. |
| **ElectricEye / Aurelian** | **Public exposure and recon pattern references** — inform `config/public-exposure-policy.yaml` and fixtures, not copied auditor code. |
| **Nisify** | **Evidence aggregation and maturity scoring reference** — informs `config/evidence-source-registry.yaml` and `fedramp20x/evidence_maturity.py`, not a Nisify fork. |
| **FedRAMP20xMCP / Knox pilot** | **FedRAMP 20x requirement and package references** — pattern/package **shape** for `config/ksi-catalog.yaml`, `fedramp20x/*`, `schemas/`; optional MCP sidecar, not the product core. |
| **OCSF** | **Event / finding vocabulary reference** — `providers/ocsf.py`, `normalization/ocsf_export.py`; we do not claim full schema compliance. |
| **AuditKit CE** | **Evidence package / report layout reference** — bundle narrative ideas; structural hints and tests (`providers/auditkit.py` where used), not a CE runtime dependency. |

**Our unique product** remains **evidence-chain correlation** and **audit-ready proof** across inventory, scanner scope, logs, alerts, tickets, exploitation review, POA&M, KSI package, and **AI derivation trace** (artifact-grounded — not LLM pass/fail).

---

## Build & validate (what we ship)

| # | Area | Where it lives |
|---|------|----------------|
| 1 | Reference sample manifest | `reference_samples/manifest.json`, `docs/reference_repo_inventory.md` |
| 2 | Adapters / importers | `providers/prowler.py`, `providers/cloudsploit.py`, `providers/ocsf.py`, … |
| 3 | Graph vocabulary | `core/evidence_graph.py`, `scripts/export_graph_cypher.py` |
| 4 | Public exposure policy | `config/public-exposure-policy.yaml`, `providers/exposure_policy.py` |
| 5 | KSI / package mapping | `config/ksi-catalog.yaml`, `fedramp20x/ksi_catalog.py`, crosswalk configs |
| 6 | Package / report / reconciliation | `fedramp20x/package_builder.py`, `core/report_writer.py`, `agent.py reconcile-20x` |
| 7 | Web explorer | `web/index.html`, `scripts/serve_web.py`, `web/sample-data/` |
| 8 | AI explanation | `api/explain.py`, `ai/*`, `core/evidence_contract.py` |
| 9 | Full gate | `scripts/validate_everything.py` |

**Final command** (from repo root `observable-security-agent/`; exit `0` when overall is PASS or WARN):

```bash
cd /Users/tkhan/IdeaProjects/security-infra/observable-security-agent

python scripts/validate_everything.py \
  --tracker fixtures/assessment_tracker/sample_tracker.csv \
  --output-root validation_run
```

Outputs include `validation_run/validation_summary.md`, `validation_run/reference_validation_summary.md`, and `validation_run/reference_reuse_audit.md`.

---

## End-to-end proof path (artifact chain)

One trace through the product—**from intake to AI—without inventing scanner or graph engines**:

```
CSV / tracker rows  ──or──  scanner export (Prowler / CloudSploit / OCSF adapters)
        →  normalized evidence  (fixtures + providers; `ScannerFinding`, `SecurityEvent`, semantic types)
        →  evidence graph       (`evidence_graph.json`, `core/evidence_graph.py`)
        →  eval result          (`eval_results.json`, `evals/*`)
        →  control mapping      (`control_mapper` / crosswalk, control IDs on rows)
        →  KSI mapping          (`ksi-catalog.yaml`, package KSI sections)
        →  finding              (package + correlation outputs)
        →  POA&M                (`poam.csv`, package POA&M)
        →  report               (`reports/assessor/`, `executive/`, `agency-ao/`; markdown + JSON mirror)
        →  web trace            (`web/index.html`, `web/sample-data/` after refresh)
        →  AI explanation       (`api/explain.py`, evidence contract — grounded in same artifacts)
```

The full harness run above exercises tracker import → gap classification → 20x package → agent loop → reconciliation → web sample refresh → deterministic AI fallback (WARN if `AI_API_KEY` unset; still exit `0`).

---

## Why this is not reinventing the wheel

We **reuse industry vocabulary and sample shapes** under `reference_samples/` (see `reference_samples/manifest.json`). We **do not** ship upstream code as our runtime. The product investment is **provable evidence chains, KSI-ready packaging, reconciliation, and audit narrative**—not another CSPM SKU.

---

## Product focus (what we are / are not)

This is **not** an AI chatbot stapled onto compliance. It is a **bounded security agent** that produces **observable, testable, audit-ready evidence** about both the **cloud environment** and the **AI agent itself** (how identity, permissions, tool use, context, approvals, logging, and policy decisions are scoped and replayable from artifacts—not narrative invention).

| This product **is** | This product **is not** |
|---------------------|-------------------------|
| A **proof engine** for control → KSI → criterion → source → result → finding → POA&M → narrative → **reconciliation** | A **CSPM scanner** (we consume scanner output; we do not compete on check volume) |
| An **evidence-correlation** layer over normalized inputs | **Only** a FedRAMP Rev4/Rev5 **crosswalk** (crosswalks configure mapping; they do not replace validation and linkage) |
| An **authorization-ready bundle** with machine + human mirrors | **Only** a **report generator** (Markdown/HTML derive from the same JSON the validator sees) |

**Evidence integrity:** we **do not invent evidence**. **Missing evidence is a first-class finding** (FAIL/PARTIAL with explicit gaps)—never backfilled by prose or LLM.

**Required chain (FedRAMP 20x path):** Rev4/Rev5 control evidence → FedRAMP 20x **KSI** → validation criterion → evidence source → machine-readable result → finding → POA&M item → assessor / executive / AO explanation → **reconciliation** proving human and machine outputs match.

**Every FAIL/PARTIAL** must support assessors with: what was evaluated; evidence used; evidence missing; impacted control/KSI; artifact that would close the gap; whether **POA&M** or **risk acceptance** applies. (Operational detail: `README.md` → *Every failed or partial result must explain*.)

**Enforcement:** `scripts/validate_outputs.py` / `core/output_validation.py` reject incomplete FAIL/PARTIAL rows in `eval_results.json`. `core/report_writer.py` emits `remediation_disposition` and aligned `eval_result_records` on each assess run.

---

## 1. Reference projects represented in `reference_samples/` (and clones)

- **Prowler**, **CloudSploit** — scanner rows / compliance / check metadata (`reference_samples/prowler/`, `reference_samples/cloudsploit/`)
- **Cartography**, **CloudGraph**, **Fix Inventory** — graph models and inventory semantics (`reference_samples/cartography/`, `reference_samples/cloudgraph/`, `reference_samples/fixinventory/`)
- **ElectricEye**, **Aurelian** — exposure / recon (`reference_samples/electriceye/`, `reference_samples/aurelian/`)
- **Nisify** — evidence model / mappings (`reference_samples/nisify/`)
- **FedRAMP20xMCP**, **Knox pilot** — 20x patterns and package examples (`reference_samples/fedramp20xmcp/`, `reference_samples/knox_20x_pilot/`)
- **OCSF** — schema excerpts (`reference_samples/ocsf/`)
- **AuditKit CE** — package / report excerpts (`reference_samples/auditkit/`)

---

## 2. What each already solves

**Scanning** — Prowler, CloudSploit, ElectricEye, Aurelian: cloud misconfiguration and exposure **inputs**.

**Graph topology** — CloudGraph, Fix Inventory, Cartography: asset and relationship **models** for analysts.

**Event schema** — OCSF: vendor-neutral security finding and event **vocabulary**.

**Evidence aggregation / maturity** — Nisify: CSF-style rollups and maturity **communication** patterns.

**FedRAMP 20x surfaces** — FedRAMP20xMCP, Knox pilot: requirement/pattern lookup and **package exemplars**.

**Evidence package inspiration** — AuditKit CE: auditor-facing bundles and report layout **ideas**.

**Public exposure checks** — ElectricEye, Prowler, Aurelian: sec-group and recon **patterns**.

---

## 3. What we reused or adapted

- **Output formats** — Prowler- and CloudSploit-style JSON/CSV rows and OCSF-shaped detections as **inputs** to our adapters (`providers/prowler.py`, `providers/cloudsploit.py`, `providers/ocsf.py`), not as our assessment model.
- **Compliance metadata** — Keys and framework fixtures informed how we **reject non-scan JSON** and preserve `Compliance`-like blobs on `ScannerFinding.metadata`.
- **Graph relationship concepts** — Cartography, CloudGraph, and Fix Inventory style “things connect to things” **mindset** informed an **evidence graph** and optional **Cypher export** for the same bundle (`core/evidence_graph.py`, `scripts/export_graph_cypher.py`); labels and edges are ours.
- **Schema vocabulary** — OCSF finding/cloud fields informed field extraction; `normalization/ocsf_export.py` carries our **`semantic_type`** in an extensions-style envelope for interoperability without claiming full OCSF compliance.
- **Evidence package structure** — AuditKit-style “bundle + artifacts + linkage” ideas informed **FedRAMP 20x** layout and a small **structural validator** (`providers/auditkit.py`) for tests—implementation remains original.

---

## 4. What they do not solve

- **Inventory vs scanner scope vs log coverage correlation**
- **Alert instrumentation validation**
- **Risky event → actor → asset → ticket → POA&M correlation**
- **High/critical vulnerability exploitation-review evidence**
- **FedRAMP 20x KSI package generation from correlated evidence**
- **Human/machine reconciliation**
- **AI derivation trace**

Those gaps are intentional product scope: they require **normalized evidence**, **evaluations**, and **authorization-ready** outputs—not a bigger scanner.

---

## 5. Our product wedge

Most tools detect misconfigurations. **This evaluates whether the security program is observable, instrumented, correlated, and audit-ready**—with a **defensible evidence chain** from control intent through KSI validation to POA&M and reconciliation, without fabricating proof.

---

## Why this is sponsor-aligned

BuildLab sponsors care that an **AI security agent** is safe to run, observable, and useful for **authorization- and operations-ready** outcomes—not a black box that mutates production. This project aligns with that bar:

- **Secure agent architecture** — batch assessment and optional read-only explain API; no ambient write credentials in the core path; outputs are files and schema-validated JSON you can review before any human relies on them.
- **AI behavior observability** — explain modes derive from **loaded artifacts** (`eval_results.json`, package JSON, graph); the web UI surfaces derivation and gaps instead of hiding model reasoning.
- **Permission and tool-use governance** — cloud collection is **explicit** (`collect-aws` / fixture packs); evaluations are **fixed rule sets**, not open-ended tool loops against your account.
- **Compliance automation** — deterministic evals, POA&M seeds, and FedRAMP **20x-style** machine-readable packages reduce manual assembly; **automation** here means traceable linkage, not silent pass/fail.
- **Evidence-backed KSI validation** — KSI rollups tie to evidence refs and eval IDs; FAIL/PARTIAL rows must cite evidence used, gaps, and remediation disposition (see `core/failure_narrative_contract.py`).
- **Threat hunting for agentic misuse** — semantic events, correlation rows, and cross-domain gaps highlight **broken observability chains** (e.g. risky change without ticket, alert, or log)—the same patterns teams hunt when AI or humans bypass controls.
- **Human/machine reconciliation** — package build records parity between Markdown mirrors and JSON; deep reconciliation artifacts stress **assessor vs. machine** alignment.

**Scope honesty:** This repository does **not** incorporate, ship, or claim any **proprietary vendor assessment frameworks** or sponsor-private ATO templates. Config uses **public NIST / FedRAMP authorization language** and our own YAML/CSV; “20x” refers to **machine-readable KSI-oriented packaging**, not a third-party commercial methodology.

---

## 6. Demo proof

**Full validation run (recommended for demos):** `validation_run/` after `scripts/validate_everything.py` (see command above).

**In-repo pointers:** `reference_samples/manifest.json`, `docs/reference_project_analysis.md`, `docs/reference_gap_matrix.md`, `docs/reference_to_implementation_traceability.md`, `docs/buildlab_reference_backed_demo.md`.

**Typical assessed outputs** (paths vary by `output-dir`): `eval_results.json`, `evidence_graph.json`, `fedramp20x-package.json`, `reports/assessor/`, `reports/executive/`, `reports/agency-ao/`.

This file—`docs/why_this_is_not_reinventing_the_wheel.md`—is the **reference-backed build justification** tying acceptance criteria, traceability, and `validate_everything` gates together.
