# Reference-Driven Gap Implementation Plan

This plan compares the reference material against Observable Security Agent and separates true gaps from intentional delegation. The goal is not to rebuild mature scanner, SIEM, inventory, or ticketing products. The goal is to make the agent excellent at ingesting their outputs, testing evidence reasonableness, and presenting an audit-ready story in the UI.

## Current Bottom Line

The platform already covers the core differentiator:

- Evidence graph, cross-domain correlation, POA&M, FedRAMP 20x package generation, reconciliation, assessor/AO/executive reports, bounded agent traces, 3PAO-style tracker classification, ConMon cadence checks, and grounded AI explanations.
- Reference samples are used as adapter contracts and design fuel, not runtime dependencies.
- This hardening pass implements the highest-risk gaps as working foundations: UI workbench panels, OCSF breadth expansion, scanner routing, ticket export normalization, graph/inventory import normalization, public exposure display, package diff display, and AI backend status display.
- Remaining follow-up is mostly depth work: more real-world dialect fixtures, richer visual polish, and optional live connector integrations.

## Implemented In This Pass

| Gap area | Implemented artifact |
| --- | --- |
| Reference/capability visibility | `web/sample-data/reference_coverage.json`, `web/sample-data/capability_inventory.json`, Explorer "Capabilities & References" panel |
| 3PAO reasonableness visibility | `web/sample-data/reasonableness_findings.json`, Explorer "3PAO Reasonable Test" panel |
| Live AWS permission/confidence coverage | `web/sample-data/live_collection_coverage.json`, Explorer "Live Collection Coverage" panel |
| ConMon workbench | `web/sample-data/conmon_workbench.json`, Explorer "ConMon Workbench" panel |
| Public exposure workbench | `web/sample-data/public_exposure_workbench.json`, Explorer "Public Exposure" panel |
| Package diff/history | `web/sample-data/package_diff.json`, Explorer "Package Diff" panel |
| AI backend status | `web/sample-data/ai_backend_status.json`, Explorer "AI Backend Status" panel |
| Evidence graph UI | SVG graph map in `web/app.js` and `web/styles.css` |
| Scanner adapter breadth | `providers/scanner_router.py` with auto detection and Nessus-like CSV support |
| OCSF breadth | Expanded `providers/ocsf.py` semantic mapping for API, auth, network, storage, logging, compute, and vulnerability records |
| Ticket export normalization | `providers/ticket_export.py` for generic/Jira-like/ServiceNow-like/Smartsheet-like CSV/JSON exports |
| Inventory graph import | `providers/inventory_graph.py` for CloudGraph/FixInventory/Cartography-like node shapes |

## Actual Gaps To Close

| Priority | Gap | Why it matters | Reference fuel | Implementation direction | Acceptance proof |
| --- | --- | --- | --- | --- | --- |
| P0 | Reference/capability visibility is not first-class in the Explorer UI | Judges should see how reference material fuels the platform without reading docs | All reference samples | Add a "Capabilities & References" panel showing 72 samples, 12 projects, adapter coverage, implemented vs partial status, and test anchors | Implemented; expand screenshots before final submission |
| P0 | 3PAO reasonableness is implemented but not visible enough in the UI | The reasonable-test is one of the strongest differentiators; it should be demoable in one click | Generic 3PAO tracker patterns, AuditKit evidence posture | Add a "Reasonable Test" panel with gap, required proof, supplied artifacts, sufficiency findings, citations, and remediation | Implemented; deepen with live reasoner output when API is running |
| P0 | Live AWS permission/confidence coverage needs a dedicated UI surface | Live environments often have denied/skipped APIs; assessors need to see impact on confidence | Prowler/ElectricEye scanner posture, AuditKit read-only posture | Add "Live Collection Coverage" panel fed by manifests: successful calls, denied calls, skipped services, affected eval confidence, region coverage | Implemented as manifest-shaped UI sample; wire live run summaries next |
| P1 | OCSF normalization is partial | OCSF is the strongest event/finding vocabulary reference; broader mappings make arbitrary environment ingestion more resilient | `ocsf-schema` samples | Expand OCSF adapter coverage for detection finding, API activity, authentication, network activity, vulnerability finding, and cloud resource events | New OCSF fixture tests and round-trip export/import tests |
| P1 | Scanner adapter breadth is still AWS/CSPM-centric | Competition inputs may include Prowler, CloudSploit, ElectricEye-like rows, Nessus-like CSV, or mixed exports | Prowler, CloudSploit, ElectricEye, Aurelian | Add a generic scanner import router with dialect detection and normalized `ScannerFinding` output; add Nessus/OpenVAS-style minimal CSV support | Import tests for multiple scanner dialects and malformed rows |
| P1 | Inventory graph import is not broad enough | CloudGraph/FixInventory/Cartography references solve inventory graph extraction; OSA should ingest their shapes rather than recreate them | CloudGraph, FixInventory, Cartography | Add optional graph/inventory import adapters that normalize nodes/edges into `EvidenceGraph` and `discovered_assets.json` | Fixture tests for graph imports and reconciliation deltas |
| P1 | Ticketing exports are semantically handled but not adapter-rich | A live assessment may hand us CSV/JSON exports from several workflow tools with different field names | AuditKit package ideas, 3PAO tracker patterns | Add ticket import router with field mapping config for generic CSV, Jira-like, ServiceNow-like, and Smartsheet-like exports; avoid vendor API dependency by default | Parser tests for each export shape and UI source badge |
| P1 | ConMon coverage is catalog-backed but lacks a cadence calendar/workbench | Annual, quarterly, monthly, weekly, and always-on obligations should be scannable in the demo | ConMon checklist and NIST/FedRAMP cadence language | Add ConMon workbench panel: obligation, cadence, last evidence date, artifact source, reasonableness gaps, next due | Unit tests and screenshot |
| P2 | Public exposure detection relies on imported findings and policy mapping | This is acceptable, but a small external-surface workbench would help show Aurelian-style value | Aurelian, Prowler, CloudSploit, ElectricEye | Add public exposure panel grouping internet-facing assets, admin ports, public buckets, public endpoints, exceptions, and missing proof | Policy tests plus web panel contract |
| P2 | Evidence graph UI is list-based, not visual enough | A feature-rich UI should make asset-event-finding-ticket-control chains obvious | CloudGraph, FixInventory, Cartography | Add an interactive graph canvas or SVG network view with filters for asset/event/finding/ticket/control/KSI and selected evidence chain | Browser/screenshot test verifies nonblank graph and no overlap |
| P2 | Reports are rich, but package diff/history is limited | Knox/AuditKit-style package confidence improves when users can compare current vs prior run | Knox pilot, AuditKit | Add package diff/reconciliation panel showing changed KSI status, new/closed findings, POA&M movement, and evidence maturity deltas | Fixture pair test and UI contract |
| P2 | AI backend status is not obvious in the UI | LLM backends are optional; judges should see deterministic fallback vs Ollama/LiteLLM/Bedrock clearly | FedRAMP20xMCP pattern lookup ideas, AI explanation layer | Add AI backend health widget: configured backend, model, deterministic fallback status, evidence contract, last response citations | API test and UI health indicator test |

## Implementation Phases

### Phase 1 — Judge-Visible Auditability Panels

Build the UI panels that make existing strengths obvious:

- Capabilities & References
- 3PAO Reasonable Test
- Live Collection Coverage
- ConMon Workbench
- AI Backend / Evidence Contract status

Backend work should be minimal in this phase: generate compact JSON summaries under `web/sample-data/` and `output/`, then render them in `web/index.html`, `web/app.js`, and `web/styles.css`.

Acceptance:

- `tests/test_web_sample_data_contract.py` covers the new sample files.
- `tests/test_buildlab_readiness.py` checks the new panel labels and data load paths.
- Screenshot capture adds the new panels under `docs/competition/`.

### Phase 2 — Adapter Breadth

Expand ingestion so competition inputs can vary without code changes:

- Generic scanner import router with dialect detection.
- Expanded OCSF class mapping.
- Graph/inventory import adapters for CloudGraph/FixInventory/Cartography-like shapes.
- Ticket export router with configurable field aliases.

Acceptance:

- New fixtures under `tests/fixtures/`.
- Adapter tests for each dialect.
- `agent.py import-findings` and tracker workflows use shared dialect-aware CSV utilities.

### Phase 3 — Deep UI / Operator Workbench

Make the Explorer feel like a complete assessment cockpit:

- Interactive evidence graph, not only node lists.
- Public exposure workbench.
- Package diff/history view.
- Source health and adapter confidence dashboard.
- Copy/export affordances for assessor narratives, remediation plans, and evidence requests.

Acceptance:

- Browser/screenshot verification for desktop and mobile.
- Canvas/SVG nonblank checks if a graph visualization is used.
- No overlapping text or one-note visual palette.

### Phase 4 — Live Connector Ergonomics

Keep APIs read-only and optional, but make live runs smoother:

- Manifest-first live collection summary for AWS.
- Optional sidecar import commands for scanner/ticket exports.
- Clear permission-impact messages when cloud APIs are denied.
- Source registry entries for Wazuh/Splunk/CloudWatch-style logs without requiring live credentials in demo data.

Acceptance:

- Live mode can run with clean or sparse accounts.
- Denied permissions degrade confidence instead of crashing.
- Guard tests prove no live identifiers land in committed sample paths.

## Deliberate Non-Goals

- Do not rebuild Prowler, CloudSploit, ElectricEye, Aurelian, CloudGraph, FixInventory, Cartography, Splunk, Wazuh, Jira, ServiceNow, or Smartsheet.
- Do not make LLM output authoritative for pass/fail. LLMs may classify unknown tracker rows, explain evidence chains, and draft remediation, but deterministic artifacts remain the audit record.
- Do not commit live raw evidence, credentials, real account IDs, real ARNs, named people, named tenants, or specific assessor/customer identifiers.

## Recommended Next Sprint

1. Add `capability_inventory.json`, `reference_coverage.json`, and `reasonableness_findings.json` generated from existing configs and sample outputs.
2. Add Explorer panels for Capabilities & References and 3PAO Reasonable Test.
3. Add Live Collection Coverage panel using existing AWS raw manifest fixtures.
4. Add tests and screenshots for those panels.
5. Then move into scanner/OCSF/ticket adapter breadth.
