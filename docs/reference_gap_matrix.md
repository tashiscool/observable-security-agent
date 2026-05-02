# Reference capability gap matrix

**Inputs:** [`docs/reference_repo_inventory.md`](reference_repo_inventory.md) (local `reference/` clone status), [`reference_samples/manifest.json`](../reference_samples/manifest.json) (tracked excerpts + `reference_directory_inventory`), and the **Observable Security Agent** codebase (`evals/`, `fedramp20x/`, `agent_loop/`, `ai/`, `core/`).

**Local clone note:** OCSF, Cartography, ElectricEye, and AuditKit Community Edition are **MISSING** as full trees under `reference/` but have **small excerpts** under `reference_samples/` per `manifest.json`. The matrix below treats those four as **“reference projects (samples/docs only)”** where a full clone is absent.

---

## Legend

### Reference projects (columns)

| Symbol | Meaning |
| ------ | ------- |
| **S** | **Already solved** — primary product value; mature in that lane. |
| **P** | **Partially solved** — some support, adjacent feature, or requires custom glue. |
| **—** | **Not solved** — out of scope, not a design goal, or only tangential. |

### Observable Security Agent (OSA)

| Symbol | Meaning |
| ------ | ------- |
| **I** | **Implemented** — in-repo logic, evals, and/or fixtures demonstrate it. |
| **P** | **Partial** — scaffold, single-provider path, or depends on external scanner/connectors. |
| **N** | **Not a goal** — deliberately delegated to ecosystem tools. |

### Recommended action (for OSA only)

| Action | Meaning |
| ------ | ------- |
| **reuse** | Run upstream tool; ingest outputs via adapter only. |
| **import** | Treat as optional dependency / sidecar (API, MCP, CLI). |
| **adapt** | Mirror data shapes, UX patterns, or schema ideas from samples/docs. |
| **do not build** | Do not recreate the crowded CSPM/inventory engine lane. |
| **build unique** | Core differentiator; keep investing here. |

---

## Executive summary (why this is not “rebuilding Prowler”)

| Reference stack | What it *owns* | What it *does not* own |
| --------------- | -------------- | ---------------------- |
| **Prowler / CloudSploit / ElectricEye / Aurelian** | Finding misconfigurations, exposure, and posture (scanner / recon **input**) | Proving **program evidence**: logs, alerts, tickets, CM, exploitation review, correlating events to **actors/assets**, rolling **FedRAMP 20x KSI packages**, **POA&M rows**, **assessor narratives**, **reconciliation**, **bounded agent** workflows with policy |
| **CloudGraph / Fix Inventory / Cartography** | **Asset/inventory graph**, snapshots, relationships | FedRAMP **assessment lifecycle**, **tracker→gap→package**, **AI explanation with evidence contract** tied to your artifacts |
| **OCSF** | **Event taxonomy** for normalization | Compliance **evaluators**, **package validation**, **report sets** |
| **Nisify** | **NIST CSF 2.0** evidence aggregation & maturity | **FedRAMP 20x** KSI rollups, **CM-8** reconciliation semantics as implemented here, **RA-5(8)** exploitation-review eval |
| **FedRAMP20xMCP** | **Requirement / pattern lookup** via MCP | Cloud evidence collection, eval pipeline, package **generation** |
| **Knox FedRAMP 20x Pilot** | **Publication examples** (schemas, machine-readable assessment) | Operational engine to produce those artifacts from **your** telemetry |
| **AuditKit CE** | Assessor **documentation / packaging** ideas (samples) | Live multi-cloud normalization + eval + agent loop in this repo |

**Our unique layer (build unique + selective reuse):** **evidence correlation** (events ↔ actors ↔ assets ↔ controls/KSIs), **deterministic evals** for audit-chain controls (logs, alerts, scanner scope, CM, exploitation review), **FedRAMP 20x package + POA&M + reports**, **human/machine reconciliation**, **instrumentation plan generation**, **assessment-tracker import → evidence gaps**, and **AI explanation** that is **grounded in artifacts** (no LLM pass/fail), inside a **bounded autonomous workflow** with explicit policy.

---

## Summary matrix (capabilities × projects)

Rows use **S / P / —** per reference project. **OSA** column uses **I / P / N** plus a short **action** keyword.

| # | Capability | Prowler | CloudSploit | CloudGraph | Fix Inv. | Aurelian | Nisify | 20x MCP | Knox pilot | OCSF† | Carto.† | Elec.† | AuditKit† | OSA | OSA action |
|---|------------|---------|-------------|------------|----------|----------|--------|---------|------------|-------|--------|--------|----------|-----|------------|
| 1 | Multi-cloud scanning | S | S | P | P | P | P | — | — | — | — | P | — | P | reuse / do not build |
| 2 | Public exposure detection | P | P | P | P | S | — | — | — | — | — | P | — | P | reuse / adapt |
| 3 | Cloud asset inventory | P | P | S | S | P | P | — | — | — | S | P | — | I | adapt / build unique |
| 4 | Asset relationship graph | — | — | S | S | P | — | — | — | — | S | — | — | I | adapt / build unique |
| 5 | OCSF / event normalization | — | — | — | — | — | — | — | — | S | — | — | — | P | adapt |
| 6 | Compliance / control mapping | S | P | P | P | — | S | P | P | — | — | — | P | I | adapt / build unique |
| 7 | NIST / FedRAMP evidence aggregation | P | — | — | — | — | S‡ | P | P | — | — | — | P | I | build unique |
| 8 | FedRAMP 20x KSI lookup | P | — | — | — | — | — | S | P | — | — | — | — | I | import / adapt |
| 9 | FedRAMP 20x package examples | — | — | — | — | — | — | — | S | — | — | — | P | I | adapt |
| 10 | POA&M generation | — | — | — | — | — | P | — | P | — | — | — | P | I | build unique |
| 11 | Centralized log coverage validation | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |
| 12 | Alert instrumentation validation | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |
| 13 | Scanner-scope coverage validation | P | P | P | P | — | — | — | — | — | — | P | — | I | build unique |
| 14 | Inventory vs cloud reconciliation | — | — | P | P | — | P | — | — | — | P | — | — | I | build unique |
| 15 | Risky event → actor → asset correlation | — | — | — | P | P | — | — | — | — | P | — | — | I | build unique |
| 16 | Risky event → ticket / CM linkage | — | — | — | — | — | — | — | — | — | — | — | P | I | build unique |
| 17 | High/critical vuln exploitation-review evidence | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |
| 18 | Generated SPL/KQL/GCP/AWS instrumentation | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |
| 19 | Auditor question generation | — | — | — | — | — | — | — | P | — | — | — | P | I | build unique |
| 20 | Assessor / executive / AO reports | — | — | — | — | — | P | — | S | — | — | — | P | I | build unique |
| 21 | Machine / human reconciliation | — | — | — | — | — | — | — | P | — | — | — | P | I | build unique |
| 22 | AI explanation grounded in artifacts | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |
| 23 | Bounded autonomous workflow | — | — | — | — | — | — | — | — | — | — | — | — | I | build unique |

† **OCSF, Cartography (Carto.), ElectricEye (Elec.), AuditKit:** assessed from **public project role** + **`reference_samples/`** (no full local clone per inventory).

‡ **Nisify** is **NIST CSF 2.0** aggregation — strong for **NIST-shaped** evidence maturity, not a drop-in for **FedRAMP 20x KSI** semantics (hence **P** on row 7 for FedRAMP-specific aggregation).

---

## Per-capability detail (OSA implementation + action)

### 1. Multi-cloud scanning

| Project | Status | Notes |
| ------- | ------ | ----- |
| Prowler / CloudSploit | S | Broad CSPM scanners. |
| Others | P / — | Exposure-focused or single-area checks. |
| **OSA** | **P** | Fixture + provider/adapters; **not** a full CSPM rewrite. |
| **Action** | **reuse / do not build** | Run Prowler/CloudSploit (or similar) as **inputs**; normalize findings. |

### 2. Public exposure detection

| Project | Status | Notes |
| ------- | ------ | ----- |
| Aurelian | S | Recon / public resource modules. |
| ElectricEye (samples) | P | AWS exposure-style checks. |
| **OSA** | **P** | Semantic mapping + policy; relies on finding/event **shape** from scanners. |
| **Action** | **reuse / adapt** | Keep public exposure logic in scanners; map to `semantic_type` / policy. |

### 3. Cloud asset inventory

| Project | Status | Notes |
| ------- | ------ | ----- |
| Fix Inventory / CloudGraph / Cartography | S | Inventory + relationships. |
| **OSA** | **I** | Declared + discovered assets in `AssessmentBundle`; reconciliation is separate. |
| **Action** | **adapt / build unique** | **Adapt** graph/inventory modeling ideas; **build** reconciliation + eval layer. |

### 4. Asset relationship graph

| Project | Status | Notes |
| ------- | ------ | ----- |
| CloudGraph / Fix Inventory / Cartography | S | Graph-first products. |
| **OSA** | **I** | `EvidenceGraph` + Cypher export patterns (tests/fixtures). |
| **Action** | **adapt / build unique** | **Adapt** relationship vocabulary; **build** evidence-chain graph for audit. |

### 5. OCSF / event normalization

| Project | Status | Notes |
| ------- | ------ | ----- |
| OCSF (samples) | S | Schema is the reference. |
| Scanners | — | Vendor-native events. |
| **OSA** | **P** | OCSF-like import/export paths; primary **fixture** pipeline is internal models. |
| **Action** | **adapt** | Align exports where helpful; do **not** fork the full OCSF project. |

### 6. Compliance / control mapping

| Project | Status | Notes |
| ------- | ------ | ----- |
| Prowler | S | Rich framework JSON packs. |
| Nisify | S | CSF control ↔ evidence mapping patterns. |
| **OSA** | **I** | `config/` crosswalks, KSI catalog, eval→control wiring. |
| **Action** | **adapt / build unique** | **Do not rebuild** entire Prowler compliance library; **build** FedRAMP 20x **rollup** + gap logic. |

### 7. NIST / FedRAMP evidence aggregation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Nisify | S | **NIST CSF 2.0** aggregation (not FedRAMP 20x KSI engine). |
| Knox pilot | P | Example **packaged** assessment artifacts. |
| **OSA** | **I** | Tracker import, evidence gaps, eval results, package builder. |
| **Action** | **build unique** | **Differentiator** vs pure CSF tooling: **audit-chain** evidence + **20x** packaging. |

### 8. FedRAMP 20x KSI lookup

| Project | Status | Notes |
| ------- | ------ | ----- |
| FedRAMP20xMCP | S | MCP requirement/pattern query surface. |
| **OSA** | **I** | In-repo KSI catalog + mapping pipeline. |
| **Action** | **import / adapt** | Optional **sidecar MCP**; keep **canonical** config in-repo. |

### 9. FedRAMP 20x package examples

| Project | Status | Notes |
| ------- | ------ | ----- |
| Knox pilot | S | Machine-readable assessment + schema examples (`reference_samples/knox_20x_pilot/`). |
| **OSA** | **I** | `fedramp20x/package_builder.py` + schemas under `schemas/`. |
| **Action** | **adapt** | Structure reports/packages like pilot **without** copying proprietary narrative. |

### 10. POA&M generation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Nisify / Knox / AuditKit (samples) | P | Maturity or narrative artifacts—not this repo’s eval-driven POA&M CSV. |
| **OSA** | **I** | POA&M items tied to gaps/evals; tracker path produces rows. |
| **Action** | **build unique** | Eval-driven POA&M is core. |

### 11. Centralized log coverage validation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Reference scanners | — | Do not prove centralized logging posture end-to-end for AU families. |
| **OSA** | **I** | `AU6_CENTRALIZED_LOG_COVERAGE` eval (`evals/central_log_coverage.py`). |
| **Action** | **build unique** | Core audit-chain proof. |

### 12. Alert instrumentation validation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Reference stack | — | Alert rule **proof** vs cloud telemetry is not their main output. |
| **OSA** | **I** | `SI4_ALERT_INSTRUMENTATION` eval. |
| **Action** | **build unique** | Core audit-chain proof. |

### 13. Scanner-scope coverage validation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Prowler / CloudSploit / EE | P | They **scan**; they don’t prove **declared** scope vs **inventory** vs **results**. |
| **OSA** | **I** | `RA5_SCANNER_SCOPE_COVERAGE` eval. |
| **Action** | **build unique** | Core audit-chain proof. |

### 14. Inventory vs cloud reconciliation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Graph/inventory tools | P | Strong **inventory**; weak on **authoritative declared baseline vs discovered** with gap **eval**. |
| **OSA** | **I** | `CM8_INVENTORY_RECONCILIATION` eval. |
| **Action** | **build unique** | Core audit-chain proof. |

### 15. Risky event → actor → asset correlation

| Project | Status | Notes |
| ------- | ------ | ----- |
| SIEM / OCSF | P | Schema helps; **no** FedRAMP eval rollup here. |
| Graph tools | P | Relationships; not assessor **eval result** packaging. |
| **OSA** | **I** | `CROSS_DOMAIN_EVENT_CORRELATION` + graph pipeline. |
| **Action** | **build unique** | Core **evidence correlation** layer. |

### 16. Risky event → ticket / change approval linkage

| Project | Status | Notes |
| ------- | ------ | ----- |
| ITSM tools | — | External. |
| AuditKit (samples) | P | Process/docs only. |
| **OSA** | **I** | `CM3_CHANGE_EVIDENCE_LINKAGE` eval. |
| **Action** | **build unique** | Core audit-chain proof. |

### 17. High/critical vulnerability exploitation-review evidence

| Project | Status | Notes |
| ------- | ------ | ----- |
| Scanners | P | Find vulns; **RA-5(8)**-style **exploitation review** proof is on customer program. |
| **OSA** | **I** | Exploitation review hooks in evals / models / tracker gaps. |
| **Action** | **build unique** | Core audit-chain proof. |

### 18. Generated SPL / KQL / GCP / AWS instrumentation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Reference stack | — | Not a generated **instrumentation plan** tied to **specific gaps**. |
| **OSA** | **I** | Instrumentation plan outputs on tracker/gap paths. |
| **Action** | **build unique** | Operationalizes closure of evidence gaps. |

### 19. Auditor question generation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Knox / AuditKit | P | Narrative / workflow inspiration. |
| **OSA** | **I** | `auditor_questions.md` from tracker import + eval outputs. |
| **Action** | **build unique** | Turns assessor comments into **traceable** questions. |

### 20. Assessor / executive / AO reports

| Project | Status | Notes |
| ------- | ------ | ----- |
| Knox pilot | S | **Example** publication-quality pack. |
| Nisify | P | Dashboard/reporting for **CSF maturity**. |
| **OSA** | **I** | `core/report_writer.py` + FedRAMP 20x report set. |
| **Action** | **build unique** | **Your** findings/KSIs drive narrative; **adapt** pilot **shape** only. |

### 21. Machine / human reconciliation

| Project | Status | Notes |
| ------- | ------ | ----- |
| Knox / AuditKit | P | Human process artifacts; not automated REC rules in this sense. |
| **OSA** | **I** | Reconciliation checks (e.g. REC-*) in validation harness. |
| **Action** | **build unique** | Explicit **human vs machine** accountability. |

### 22. AI explanation grounded in artifacts

| Project | Status | Notes |
| ------- | ------ | ----- |
| Entire reference stack | — | No shared “evidence contract” LLM layer in these repos for **your** package. |
| **OSA** | **I** | `ai/reasoning.py` + deterministic fallback; **no** LLM for pass/fail. |
| **Action** | **build unique** | Differentiator for **explainability** under audit constraints. |

### 23. Bounded autonomous workflow

| Project | Status | Notes |
| ------- | ------ | ----- |
| Reference stack | — | Not an **agent DAG** with **policy** over tracker→package. |
| **OSA** | **I** | `agent_loop/` task graph + memory + policy + trace outputs. |
| **Action** | **build unique** | Orchestration differentiator; keeps humans in loop via policy. |

---

## Reuse posture by upstream (quick reference)

| Upstream | Posture |
| -------- | ------- |
| **Prowler** | **reuse** output JSON; **adapt** compliance key density; **do not build** scanner. |
| **CloudSploit** | **reuse** as external engine (**GPL** — no source commingling); ingest results only. |
| **CloudGraph / Fix Inventory / Cartography** | **adapt** graph & inventory modeling; **reuse** as optional data source. |
| **Aurelian / ElectricEye** | **reuse** for exposure/recon **signals**; map to internal semantic types. |
| **Nisify** | **adapt** CSF evidence envelope patterns; **do not conflate** with FedRAMP 20x KSI engine. |
| **FedRAMP20xMCP** | **import** as optional lookup **sidecar**; keep **source-of-truth** config in-repo. |
| **Knox pilot / AuditKit samples** | **adapt** package/report **structure**; verify terms before redistribution. |
| **OCSF** | **adapt** event classes for interchange; **do not vendor** full schema tree. |

---

## Bottom line

- **We are not reinventing Prowler, CloudSploit, CloudGraph, Fix Inventory, or Cartography** as cloud **scanners** or primary **inventory graph databases**. The matrix shows those lanes as **S** where they rightly win; OSA is **P** or **do not build** there.
- **We are not reinventing OCSF**; we **adapt** it for normalization where useful.
- **We are not replacing Nisify for NIST CSF maturity dashboards**; we **overlap on “evidence aggregation”** only at a high level and **differentiate** on **FedRAMP 20x** and **continuous assessment-chain** evals.
- **Our build-unique layer** is **rows 10–23**: **audit evidence-chain evaluators**, **correlation**, **20x package + POA&M + reports + reconciliation**, **instrumentation + auditor questions**, and **bounded agent + grounded AI explanation**—the “**prove the security program can demonstrate detect → correlate → ticket → remediate → review**” story that CSPM alone does not carry.

---

*Matrix version: 1.0 — aligned with repository state documented in `docs/reference_repo_inventory.md` and `reference_samples/manifest.json`.*
