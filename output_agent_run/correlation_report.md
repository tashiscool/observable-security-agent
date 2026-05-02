# Correlation assessment report

## Executive summary

Overall result: **FAIL**.
Evaluations: 12 PASS, 0 PARTIAL, 1 FAIL, 1 OPEN.
Primary semantic type: `assessment.tracker_loaded` on asset `assessment_tracker` (provider `assessment_tracker`).

## What was assessed

- **Semantic event:** `assessment.tracker_loaded` (ref `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/output_agent_run/scenario_from_tracker/cloud_events.json#0`).
- **Asset evidence:** declared_inventory=False, discovered_cloud_asset=False, scanner_scope=False, central_log_seen_last_24h=False, criticality=medium.
- **AssessmentBundle:** 0 assets, 1 events, 0 findings, 0 alert rules, 0 tickets.

## Evidence chain summary

- **agent_approval_gates**: PASS
- **agent_auditability**: PASS
- **agent_memory_context_safety**: PASS
- **agent_permission_scope**: PASS
- **agent_policy_violations**: PASS
- **agent_tool_governance**: PASS
- **alert_rule**: FAIL
- **asset_in_inventory**: PASS
- **central_logging**: PASS
- **change_ticket**: PASS
- **event_correlation**: PASS
- **exploitation_review**: PASS
- **poam_entry**: OPEN
- **scanner_scope**: PASS

## Failed evaluations

- **SI4_ALERT_INSTRUMENTATION** (FAIL): Alert rule catalog is empty.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): No enabled alert rule covers logging.audit_disabled.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): No enabled alert rule covers network.public_admin_port_opened.

## Partial evaluations

*missing: no evaluations in this category.*

## Correlated risky events

A **correlated risky event** is a semantically typed signal listed in the scenario's `correlations.json`. Each row is checked against the same cross-domain expectations as the primary incident: authoritative inventory, scanner scope, active central logging, enabled alerts with recipients, and change or vulnerability linkage. Missing links are reported as gaps (FAIL/PARTIAL)—they are not treated as if evidence were present.


## Control impact

- AC-2
- AC-2(4)
- AC-2(7)
- AC-3
- AC-4
- AC-6
- AU-12
- AU-2
- AU-3
- AU-3(1)
- AU-5
- AU-6
- AU-6(1)
- AU-6(3)
- AU-7
- AU-8
- AU-9
- AU-9(2)
- CA-5
- CA-7
- CM-10
- CM-11
- CM-3
- CM-4
- CM-5
- CM-6
- CM-8
- CM-8(1)
- CM-8(3)
- CP-10
- CP-9
- IA-5
- IR-4
- MA-2
- MA-3
- MA-4
- MA-5
- RA-5
- RA-5(3)
- RA-5(5)
- RA-5(6)
- RA-5(8)
- SA-10
- SA-9
- SC-28
- SC-7
- SI-12
- SI-2
- SI-3
- SI-4
- SI-4(1)
- SI-4(16)
- SI-4(4)

## Recommended remediation sequence

1. **SI4_ALERT_INSTRUMENTATION**: Generate SPL/KQL/GCP/AWS query.; Add enabled alert.; Add recipient list.; Produce sample alert evidence.; Link alert to incident/change response workflow.

## Generated artifacts

- `eval_results.json` (machine-readable evaluations).
- `correlations.json` (present).
- `poam.csv` (rows generated this run, best-effort count: 1).
- `instrumentation_plan.md` (present).
- `evidence_graph.json` (nodes: 6, edges: 2).

---

## Detailed evaluation results

Per-evaluation evidence and gaps exactly as emitted by the evaluation engine.

#### CM8_INVENTORY_RECONCILIATION — **PASS**

- No declared inventory records and no discovered cloud assets in scope.
- **Gap:** No declared inventory rows and no discovered assets to reconcile.

#### RA5_SCANNER_SCOPE_COVERAGE — **PASS**

- No scanner scope inputs present.
- **Gap:** No declared inventory, discovered assets, or scanner targets to assess.

#### AU6_CENTRALIZED_LOG_COVERAGE — **PASS**

- No centralized logging evidence inputs present.
- **Gap:** No declared inventory, assets, or log sources to assess.

#### SI4_ALERT_INSTRUMENTATION — **FAIL**

- Alert rule catalog is empty.
- No enabled alert rule covers logging.audit_disabled.
- No enabled alert rule covers network.public_admin_port_opened.
- **Gap:** No alert rules are defined while security-relevant semantic events require instrumentation.; No enabled alert rule covers logging.audit_disabled.; No enabled alert rule covers network.public_admin_port_opened.

#### CROSS_DOMAIN_EVENT_CORRELATION — **PASS**

- No in-scope risky semantic events were present in the security event stream.
- **Gap:** Cross-domain correlation: no risky semantic events in scope.

#### RA5_EXPLOITATION_REVIEW — **PASS**

- No open High/Critical vulnerability findings in scope.
- **Gap:** RA-5(8): no open High/Critical scanner findings require exploitation review in this bundle.

#### CM3_CHANGE_EVIDENCE_LINKAGE — **PASS**

- No in-scope risky change events or vulnerability remediations require change linkage.
- **Gap:** CM-3/SI-2: no risky change semantics or open High/Critical findings require change ticket linkage in this bundle.

#### AGENT_TOOL_GOVERNANCE — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### AGENT_PERMISSION_SCOPE — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### AGENT_MEMORY_CONTEXT_SAFETY — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### AGENT_APPROVAL_GATES — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### AGENT_POLICY_VIOLATIONS — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### AGENT_AUDITABILITY — **PASS**

- No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.

#### CA5_POAM_STATUS — **OPEN**

- Added 1 POA&M row(s) for failing/partial evaluations (duplicates skipped: 0).
- SI4_ALERT_INSTRUMENTATION: FAIL
- **Gap:** Continuous monitoring evidence incomplete; new POA&M rows written to poam.csv.
