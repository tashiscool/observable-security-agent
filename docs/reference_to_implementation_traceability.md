# Reference → implementation traceability

This document maps **major product features** to **upstream reference projects**, **checked-in reference samples** (`reference_samples/`, listed in `reference_samples/manifest.json`), **implementation paths**, **tests**, and **what stays unique** to Observable Security Agent (OSA).

For narrative context, see also [`reference_gap_matrix.md`](reference_gap_matrix.md) and [`fedramp20x_reference_lessons.md`](fedramp20x_reference_lessons.md).

---

## Feature: Prowler adapter

- **Reference project(s) used:** **prowler-cloud/prowler** — universal scan row shape, compliance sidecars, check metadata.
- **Reference sample file(s):** `reference_samples/prowler/outputs/scan_result_sample.json`, `scan_result_sample.csv`; `reference_samples/prowler/checks/aws_iam_user_accesskey_unused.metadata.json`; `reference_samples/prowler/compliance/aws_well_architected_framework_reliability_pillar_aws.json`; `reference_samples/prowler/schemas/output_metadata_fixture.json`; `reference_samples/prowler/outputs/generic_compliance_fixture.json`; Prowler docs excerpts under `reference_samples/prowler/docs/`.
- **Implementation files affected:** `providers/prowler.py` (CSV/JSON iteration, `ScannerFinding` mapping, public-exposure semantic events); `agent.py` (`import-findings`); optional touchpoints in `core/models.py`, `config/public-exposure-policy.yaml` (check-id substring alignment).
- **Tests added:** `tests/test_prowler_adapter.py`, `tests/test_import_findings.py`, `tests/test_reference_backed_samples.py`, `tests/test_reference_sample_adapters.py`, fixtures under `tests/fixtures/` as needed.
- **What remains unique to our product:** OSA does not ship Prowler. We **ingest** representative outputs, map to **internal semantic types**, tie findings into **evidence graph**, **KSI / eval readiness**, **POA&M**, **20x packages**, and **reconciliation** — not multi-cloud CSPM execution or Prowler’s own report UX.

---

## Feature: CloudSploit adapter

- **Reference project(s) used:** **aquasecurity/cloudsploit** — plugin-oriented CSPM result rows (GPL-3.0 engine studied via samples only).
- **Reference sample file(s):** `reference_samples/cloudsploit/outputs/scan_result_sample.json`, `scan_result_sample.csv`; `reference_samples/cloudsploit/checks/publicIpAddress.js` (read-only excerpt); README and result-semantics excerpts under `reference_samples/cloudsploit/docs/` and `outputs/result_object_semantics_excerpt.md`.
- **Implementation files affected:** `providers/cloudsploit.py`; `agent.py` (`import-findings`); alignment with exposure semantics via `config/public-exposure-policy.yaml` where plugin text overlaps known patterns.
- **Tests added:** `tests/test_cloudsploit_adapter.py`, `tests/test_import_findings.py`, `tests/test_reference_sample_adapters.py`.
- **What remains unique to our product:** Same boundary as Prowler: **adapter-only**, no vendored GPL engine. Uniqueness is **downstream correlation** (assets, logs, tickets, KSI rows, packages) and **policy-governed** explanations — not CloudSploit’s plugin runtime.

---

## Feature: OCSF import / export

- **Reference project(s) used:** **ocsf/ocsf-schema** — Detection/Finding vocabulary, cloud context, extensions philosophy.
- **Reference sample file(s):** `reference_samples/ocsf/schemas/finding.json`, `cloud.json`, `version.json`; `reference_samples/ocsf/examples/base_event.json`; `reference_samples/ocsf/docs/README_excerpt.md`, `extensions_excerpt.md`.
- **Implementation files affected:** `providers/ocsf.py` (import path to `ScannerFinding` / events); `normalization/ocsf_export.py` (“OCSF-like” bundle export with explicit non-compliance label); `agent.py` (`import-findings`, `export-ocsf`); `schemas/` interchange where documented.
- **Tests added:** `tests/test_ocsf_adapter.py`, `tests/test_import_findings.py`, `tests/test_reference_sample_adapters.py`.
- **What remains unique to our product:** We do **not** claim full OCSF schema compliance. Uniqueness is **semantic preservation** (`semantic_type`, extensions bag), **bundle packaging** next to FedRAMP 20x artifacts, and **eval-driven** readiness — not maintaining the upstream taxonomy as a product.

---

## Feature: Public exposure policy

- **Reference project(s) used:** **jonrau1/ElectricEye** (sec-group rule catalog pattern); **praetorian-inc/aurelian** (public-resources recon narrative); **Prowler** / **CloudSploit** (check IDs and failure text that inform `match_check_id_substrings` / keywords).
- **Reference sample file(s):** `reference_samples/electriceye/checks/electriceye_secgroup_auditor_config.json`; Aurelian excerpts: `reference_samples/aurelian/recon_patterns/aws_recon_public_resources.md`, `docs/aurelian_aws_recon_excerpt.md`; optional ElectricEye policy JSON and README excerpts under `reference_samples/electriceye/`.
- **Implementation files affected:** `config/public-exposure-policy.yaml`; `providers/exposure_policy.py`; `providers/electriceye.py` where used for ElectricEye-shaped inputs; normalizers / adapters that emit `network.public_*` events (e.g. Prowler, CloudSploit paths); `docs/public_exposure_reference_harvest.md`.
- **Tests added:** `tests/test_public_exposure_policy.py`, `tests/test_public_admin_scenario_coverage.py`, `tests/test_prowler_adapter.py` / `tests/test_cloudsploit_adapter.py` (semantic events), `tests/test_reference_sample_adapters.py` (policy ↔ ElectricEye sample).
- **What remains unique to our product:** The YAML is **our** single catalog linking ports, **semantic types**, KSI hints, and instrumentation expectations. Uniqueness is **fed into evaluators and packages**, not copying upstream auditor code.

---

## Feature: Evidence graph

- **Reference project(s) used:** **lyft/cartography** (Neo4j asset graph, module metadata); **cloudgraphdev/cli** (GraphQL CSPM / graph query positioning); **fixinventory/fixinventory** (inventory graph / collector fixture ideas).
- **Reference sample file(s):** Cartography: `reference_samples/cartography/docs/README_excerpt.md`, `AGENTS_excerpt.md`, `graph_models/cartography_metadata_schema.md`, `schemas/detector_expectations_example.json`; CloudGraph: `reference_samples/cloudgraph/docs/README_excerpt.md`, `graph_models/examples_entrypoint.txt`, `schemas/cli_package_identity.json`; Fix Inventory: `reference_samples/fixinventory/graph_models/fixlib_readme_excerpt.md`, collector JSON fixtures under `reference_samples/fixinventory/`.
- **Implementation files affected:** `core/evidence_graph.py` (nodes, canonical `REL_*` edges, Cypher helpers); consumers in pipeline / package code; `scripts/export_graph_cypher.py` if present.
- **Tests added:** `tests/test_evidence_graph.py`, `tests/test_event_correlation.py` (graph-related assertions), `tests/test_reference_sample_adapters.py` (Cartography Cypher ↔ `REL_*` traceability).
- **What remains unique to our product:** The graph models **the** in-assessment **FedRAMP evidence chain** (inventory, scanner coverage, logs, alerts, tickets, POA&M, KSI) — not AWS-only sync jobs or CloudGraph’s schema-as-a-service. Relationship names and JSON shape are **OSA-specific**.

---

## Feature: KSI catalog / FedRAMP 20x package

- **Reference project(s) used:** **KevinRabun/FedRAMP20xMCP** (pattern / MCP-oriented requirement lookup); **Knox-Gov/fedramp_20x_pilot** (pilot package and validation JSON shapes); **guardian-nexus/AuditKit-Community-Edition** (evidence bundle / report documentation); **prowler** / **ocsf-schema** (interop fields in outputs, not package authority).
- **Reference sample file(s):** `reference_samples/fedramp20xmcp/mappings/ksi_patterns.yaml`, `requirements/server.json`, `requirements/PATTERN_SCHEMA_V2_excerpt.md`, `docs/ADVANCED-SETUP.md`; Knox: `reference_samples/knox_20x_pilot/package_examples/*.json`, `schemas/fedramp-output-schema.json`, reports/docs excerpts; AuditKit: `reference_samples/auditkit/evidence_packages/examples_README.md`, framework doc excerpts.
- **Implementation files affected:** `config/ksi-catalog.yaml`, `config/control-crosswalk.yaml`, `config/evidence-source-registry.yaml`, `fedramp20x/ksi_catalog.py`, `fedramp20x/package_builder.py`, `fedramp20x/schema_validator.py`, `fedramp20x/finding_builder.py`, `fedramp20x/poam_builder.py`, `fedramp20x/report_builder.py`, `fedramp20x/evidence_registry.py`, `providers/auditkit.py` (optional bundle-shape validation), `schemas/fedramp20x-package.schema.json` (and related).
- **Tests added:** `tests/test_ksi_catalog.py`, `tests/test_fedramp20x_package.py`, `tests/test_fedramp20x_top_package.py`, `tests/test_tracker_to_20x.py`, `tests/test_schema_validator_20x.py`, `tests/test_finding_builder.py`, `tests/test_poam_builder.py`, `tests/test_agent_ksi_fedramp.py`.
- **What remains unique to our product:** **Nested** `fedramp20x-package.json`, **checksum / evidence-links** discipline, **tracker → gap → package** automation, **reconciliation** with markdown mirrors — not MCP-only lookup or a frozen Knox clone.

---

## Feature: Evidence maturity scoring

- **Reference project(s) used:** **clay-good/nisify** (NIST CSF 2.0–style evidence aggregation / maturity communication patterns — we mirror *ideas* in registry prose, not Nisify code); **ocsf-schema** / **Knox pilot** (structured vs narrative evidence tiers as design contrast).
- **Reference sample file(s):** `reference_samples/nisify/` — `docs/config.example.yaml`, `evidence_model/*.json`, `mappings/*.json`, `reports/README_product_excerpt.md`, mapping doc excerpt.
- **Implementation files affected:** `fedramp20x/evidence_maturity.py`; `fedramp20x/evidence_registry.py`; `config/evidence-source-registry.yaml` (comments on connector/maturity patterns); call sites in package or report builders.
- **Tests added:** `tests/test_evidence_maturity.py`, `tests/test_evidence_registry.py`, package tests that assert maturity facets on builds.
- **What remains unique to our product:** Scoring is **tied to our evidence source registry and KSI catalog**, feeding **20x validation** and **executive rollups** — not shipping Nisify connectors or CSF-only dashboards.

---

## Feature: Reports (assessor / executive / AO)

- **Reference project(s) used:** **AuditKit CE** (assessor-facing bundle layout ideas); **Knox FedRAMP 20x pilot** (machine-readable assessment + summary objects); **nisify** (report product excerpt); **FedRAMP20xMCP** (pattern/findings phrasing for controls); **Prowler** docs excerpts (multi-format export expectations).
- **Reference sample file(s):** AuditKit: `reference_samples/auditkit/evidence_packages/examples_README.md`, `reports/cli_reference_stub.html`, doc excerpts; Knox: `reports/machine-readable-assessment_overview.md`, package examples; Nisify: `reference_samples/nisify/reports/README_product_excerpt.md`; Prowler: reporting tutorial excerpts under `reference_samples/prowler/docs/`.
- **Implementation files affected:** `core/report_writer.py`, `fedramp20x/report_builder.py`, `fedramp20x/reconciliation.py`; CLI subcommands that generate markdown bundles; templates under `docs/` or report modules as applicable.
- **Tests added:** `tests/test_report_writer_bundle.py`, `tests/test_report_outputs.py`, `tests/test_assessor_report_bundle.py`, `tests/test_executive_report_bundle.py`, `tests/test_agency_ao_report_bundle.py`, `tests/test_deep_reconciliation.py`.
- **What remains unique to our product:** Reports are **grounded in eval results, gaps, and package JSON**, with **reconciliation** sections and **failure narratives** — not static templates divorced from telemetry.

---

## Feature: Web explorer

- **Reference project(s) used:** **cloudgraph-cli** — **contrast only**: graph-as-product and remote GraphQL exploration vs our static **evidence explorer** bundled with a **local** assessment output. **cartography** / **fixinventory** — optional mental model for “inventory vs graph UI” boundaries (no shared frontend code).
- **Reference sample file(s):** `reference_samples/cloudgraph/docs/README_excerpt.md`, `graph_models/examples_entrypoint.txt` (documentation URLs pointer).
- **Implementation files affected:** `web/index.html`, `scripts/serve_web.py`, sample data under `web/sample-data/` (if present), any JS/CSS assets next to `web/`.
- **Tests added:** `tests/test_web_sample_data_contract.py`, `tests/test_web_explorer_tracker.py`.
- **What remains unique to our product:** The UI is a **local, read-only** view of **our** package / tracker / correlation JSON — not a multi-tenant graph console.

---

## Feature: AI explain panel

- **Reference project(s) used:** **FedRAMP20xMCP** — optional **adjacency**: external MCP servers can answer requirement text; our panel is **artifact-grounded**. **AuditKit** / **Knox** docs — examples of assessor narrative without prescribing LLM behavior.
- **Reference sample file(s):** FedRAMP20xMCP: `reference_samples/fedramp20xmcp/docs/ADVANCED-SETUP.md`, `requirements/server.json`; AuditKit SECURITY/getting-started excerpts (permissions / tooling expectations).
- **Implementation files affected:** `api/explain.py`, `api/server.py`, `core/evidence_contract.py`, `ai/reasoning.py`, `ai/fallbacks.py`, `ai/prompts.py`; static or web hooks that call the explain API.
- **Tests added:** `tests/test_api_explain.py`, `tests/test_ai_reasoning.py`.
- **What remains unique to our product:** Explanations are **bound to an evidence contract** (deterministic footers, artifact clauses, hallucination avoidance) — not open-ended control Q&A as the sole truth source.

---

## Feature: Threat-hunt / agentic-risk evals

- **Reference project(s) used:** **Prowler** / **CloudSploit** / **ElectricEye** — **inputs** (scanner findings, exposure posture) consumed by scenarios; **cartography** / **aurelian** — breadth analogues for “what attackers see” vs **our** bounded agent policy; **fixinventory** — inventory/drift tone for CM-8 style evals.
- **Reference sample file(s):** Scanner outputs under `reference_samples/prowler/outputs/`, `reference_samples/cloudsploit/outputs/`; `reference_samples/electriceye/` excerpts; optional inventory fixtures from `reference_samples/fixinventory/`.
- **Implementation files affected:** `core/threat_hunt_agentic.py`, `core/secure_agent_architecture.py`, `agent_loop/*`, `evals/agent_*`, `evals/threat_hunt*.py`, `evals/vulnerability_exploitation_review.py`; fixtures `fixtures/scenario_agentic_risk/`, `fixtures/scenario_20x_readiness/`.
- **Tests added:** `tests/test_threat_hunt_agentic.py`, `tests/test_scenario_agentic_risk.py`, `tests/test_secure_agent_architecture.py`, `tests/test_vulnerability_exploitation_review.py`, `tests/test_agent_evals.py`, `tests/test_agent_loop.py`.
- **What remains unique to our product:** **Policy-bound agent loop**, **tool governance**, **memory/trace contracts**, and **deterministic eval gates** on agentic risk — not upstream hunter frameworks.

---

## Reference project index (every upstream name appears)

| Reference project | Role in OSA |
|-------------------|------------|
| **auditkit** | Evidence package layout, assessor HTML/doc patterns, framework doc tone. |
| **aurelian** | Public-exposure recon narrative vs our YAML policy. |
| **cartography** | Asset-graph and metadata concepts → `evidence_graph` edge vocabulary. |
| **cloudgraph-cli** | Graph/CSPM UX contrast → web explorer positioning. |
| **cloudsploit** | CSPM row shape → adapter only. |
| **electriceye** | Sec-group rule catalog → `public-exposure-policy.yaml` alignment. |
| **FedRAMP20xMCP** | KSI/requirement pattern examples; MCP adjacency to explain/KSI. |
| **fixinventory** | Inventory/graph collector fixtures → inventory–graph eval mental model. |
| **knox-fedramp-20x-pilot** | Pilot package/validation JSON → our package field parity goals. |
| **nisify** | Maturity/aggregation narrative → registry + `evidence_maturity` scoring. |
| **ocsf-schema** | Event/finding taxonomy → import/export interchange. |
| **prowler** | Universal finding rows + compliance metadata → adapter + policy strings. |

---

Reference projects provide scanner outputs, graph ideas, schemas, and package examples. Our product uniquely correlates evidence across inventory, scanner scope, logs, alerts, tickets, exploitation review, POA&M, KSI reports, and AI explanations.
