# Agent run summary — workflow `tracker-to-20x`

**Started:** 2026-05-06T03:08:14.358297+00:00  
**Output directory:** `<tmp>/validation_run/agent_run_tracker`  
**Package output:** `<tmp>/validation_run/agent_run_tracker/package_tracker`  
**Input:** `<repo>/fixtures/assessment_tracker/sample_tracker.csv`  
**Status:** **SUCCESS**  

## Autonomy contract

Allowed autonomous actions (categorical contract):
- **parse** — Parse user-supplied input files (CSV/TSV/text/JSON) into typed records.
- **classify** — Classify records into typed buckets (gap types, severities, owners).
- **normalize** — Normalize partial / empty evidence envelopes; never invent assets.
- **evaluate** — Run registered evaluations against loaded evidence and emit EvalResults.
- **map** — Map controls / evals to KSIs; map evidence into the package graph.
- **package** — Build the FedRAMP 20x package and POA&M items from typed records.
- **report** — Render assessor / executive / agency-AO / reconciliation markdown reports.
- **reconcile** — Run REC-001..REC-010 deterministic parity checks across machine + human views.
- **validate** — Validate output schemas + FAIL/PARTIAL narrative contract.
- **explain** — Write the agent_run_summary.md / agent_run_trace.json explanation files.

Blocked actions (require human approval):
- **cloud_modification** — Apply, mutate, or revert resources via cloud-provider APIs (AWS/Azure/GCP).
- **permission_change** — Modify IAM / RBAC / policies in live directories or cloud accounts.
- **destructive_change** — Delete or overwrite production data; modify any non-local resource.
- **external_notification** — Send email, Slack, PagerDuty, SMS, webhooks, or any external alert.
- **real_ticket_create** — Create or update tickets in Jira / ServiceNow / GitHub / external systems.
- **email_send** — Compose or send any email (transactional or otherwise).

## Task graph

| # | Task | Category | Action | Status | Started | Completed | Artifacts |
|---|------|----------|--------|--------|---------|-----------|-----------|
| 1 | `ingest_tracker` | `parse` | `parse.assessment_tracker` | **success** | 2026-05-06T03:08:14.358486+00:00 | 2026-05-06T03:08:14.365259+00:00 | `declared_inventory.csv`, `scanner_targets.csv`, `scanner_findings.json`, `central_log_sources.json`, `alert_rules.json`, `tickets.json`, `poam.csv`, `discovered_assets.json`, `cloud_events.json`, `tracker_items.json`, `evidence_gaps.json`, `auditor_questions.md` |
| 2 | `classify_rows` | `classify` | `classify.tracker_rows_to_evidence_gaps` | **success** | 2026-05-06T03:08:14.365268+00:00 | 2026-05-06T03:08:14.365357+00:00 | `evidence_gaps.json` |
| 3 | `normalize_evidence` | `normalize` | `normalize.scenario_evidence_envelopes` | **success** | 2026-05-06T03:08:14.365363+00:00 | 2026-05-06T03:08:14.365399+00:00 | `declared_inventory.csv`, `scanner_targets.csv`, `scanner_findings.json`, `central_log_sources.json`, `alert_rules.json`, `tickets.json`, `poam.csv`, `discovered_assets.json`, `cloud_events.json` |
| 4 | `build_evidence_graph` | `evaluate` | `evaluate.build_evidence_graph` | **success** | 2026-05-06T03:08:14.365404+00:00 | 2026-05-06T03:08:14.366044+00:00 | — |
| 5 | `run_cloud_evals` | `evaluate` | `evaluate.run_cloud_control_evals` | **success** | 2026-05-06T03:08:14.366050+00:00 | 2026-05-06T03:08:14.628874+00:00 | `eval_results.json`, `evidence_graph.json` |
| 6 | `run_tracker_gap_evals` | `evaluate` | `evaluate.tracker_evidence_gap_analysis` | **success** | 2026-05-06T03:08:14.628937+00:00 | 2026-05-06T03:08:14.632828+00:00 | `tracker_gap_report.md`, `tracker_gap_matrix.csv`, `tracker_gap_eval_results.json`, `tracker_instrumentation_plan.md`, `tracker_poam.csv` |
| 7 | `run_agent_security_evals` | `evaluate` | `evaluate.agent_security_evals` | **skipped** | 2026-05-06T03:08:14.632841+00:00 | 2026-05-06T03:08:14.632892+00:00 | — |
| 8 | `map_to_ksi` | `map` | `map.controls_evals_to_ksis` | **success** | 2026-05-06T03:08:14.632899+00:00 | 2026-05-06T03:08:14.633697+00:00 | `eval_results.json` |
| 9 | `generate_findings` | `evaluate` | `evaluate.generate_findings` | **success** | 2026-05-06T03:08:14.633709+00:00 | 2026-05-06T03:08:14.634098+00:00 | `preview_findings.json` |
| 10 | `generate_poam` | `package` | `package.generate_poam_drafts` | **success** | 2026-05-06T03:08:14.634105+00:00 | 2026-05-06T03:08:14.634219+00:00 | `poam.csv`, `tracker_poam.csv`, `preview_poam_summary.json` |
| 11 | `build_package` | `package` | `package.build_fedramp20x_package` | **success** | 2026-05-06T03:08:14.634225+00:00 | 2026-05-06T03:08:14.776256+00:00 | `fedramp20x-package.json` |
| 12 | `generate_reports` | `report` | `report.generate_20x_reports` | **success** | 2026-05-06T03:08:14.776277+00:00 | 2026-05-06T03:08:14.783280+00:00 | `assessor-summary.md`, `executive-summary.md`, `ao-risk-brief.md`, `reconciliation_report.md` |
| 13 | `reconcile` | `reconcile` | `reconcile.deep_reconciliation` | **success** | 2026-05-06T03:08:14.783303+00:00 | 2026-05-06T03:08:14.787838+00:00 | `reconciliation.json` |
| 14 | `validate_outputs` | `validate` | `validate.package_schema_and_narrative_contract` | **success** | 2026-05-06T03:08:14.787854+00:00 | 2026-05-06T03:08:14.805010+00:00 | `fedramp20x-package.json`, `eval_results.json` |
| 15 | `explain_summary` | `explain` | `explain.write_agent_run_summary` | **success** | 2026-05-06T03:08:14.805024+00:00 | 2026-05-06T03:08:14.805383+00:00 | `agent_run_summary.md` |

## Errors

_No errors recorded._

## Trace

See `agent_run_trace.json` for the full machine-readable trace including per-task inputs, outputs, policy decisions, and artifact paths.
