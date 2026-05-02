# Correlation assessment report

## Executive summary

Overall result: **FAIL**.
Evaluations: 0 PASS, 0 PARTIAL, 7 FAIL, 1 OPEN.
Primary semantic type: `network.public_admin_port_opened` on asset `prod-api-01` (provider `aws`).

## What was assessed

- **Semantic event:** `network.public_admin_port_opened` (ref `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0`).
- **Asset evidence:** declared_inventory=True, discovered_cloud_asset=True, scanner_scope=False, central_log_seen_last_24h=False, criticality=high.
- **AssessmentBundle:** 5 assets, 7 events, 3 findings, 4 alert rules, 3 tickets.

## Evidence chain summary

- **alert_rule**: FAIL
- **asset_in_inventory**: FAIL
- **central_logging**: FAIL
- **change_ticket**: FAIL
- **event_correlation**: FAIL
- **exploitation_review**: FAIL
- **poam_entry**: OPEN
- **scanner_scope**: FAIL

## Failed evaluations

- **CM8_INVENTORY_RECONCILIATION** (FAIL): Declared inventory contains duplicate name values; resolve naming collisions.
- **CM8_INVENTORY_RECONCILIATION** (FAIL): Declared inventory lists the same asset_id on multiple rows — authoritative IIW conflict.
- **CM8_INVENTORY_RECONCILIATION** (FAIL): Declared inventory record Production API (inv-prod-api-dupname) is in boundary but has no matching discovered cloud asset.
- **CM8_INVENTORY_RECONCILIATION** (FAIL): Discovered asset rogue-prod-worker-99 is not present in declared inventory.
- **CM8_INVENTORY_RECONCILIATION** (FAIL): Discovered production-class asset `rogue-prod-worker-99` is absent from authoritative inventory (rogue asset risk).
- **RA5_SCANNER_SCOPE_COVERAGE** (FAIL): prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- **RA5_SCANNER_SCOPE_COVERAGE** (FAIL): prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- **RA5_SCANNER_SCOPE_COVERAGE** (FAIL): prod-api-standby-02 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- **RA5_SCANNER_SCOPE_COVERAGE** (FAIL): Discovered production compute asset `prod-api-01` has no scanner target coverage (not explicitly exempt).
- **RA5_SCANNER_SCOPE_COVERAGE** (FAIL): Discovered production compute asset `rogue-prod-worker-99` has no scanner target coverage (not explicitly exempt).
- **AU6_CENTRALIZED_LOG_COVERAGE** (FAIL): prod-api-01 requires logging but has no active central log source.
- **AU6_CENTRALIZED_LOG_COVERAGE** (FAIL): prod-api-01 requires logging but has no active central log source.
- **AU6_CENTRALIZED_LOG_COVERAGE** (FAIL): Declared `Production API` requires logging but has no matching discovered asset to verify sources.
- **AU6_CENTRALIZED_LOG_COVERAGE** (FAIL): prod-storage-01 requires logging but has no active central log source.
- **AU6_CENTRALIZED_LOG_COVERAGE** (FAIL): Critical compute asset `prod-api-01` lacks an active central log source seen within the last 24h window.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): No enabled alert rule covers compute.untracked_asset_created.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): Alert rule AC-2 — IAM admin role / policy attachment covers identity.admin_role_granted and has recipients soc@example.com, iam-governance@example.com.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): Alert rule AU-12 — CloudTrail StopLogging / DeleteTrail attempts covers logging.audit_disabled and has recipients soc@example.com.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): Alert rules reference network.public_admin_port_opened but none are enabled with recipients.
- **SI4_ALERT_INSTRUMENTATION** (FAIL): Alert rule `spl-ss-002` covers observed semantics ['logging.audit_disabled'] but has no sample_alert_ref and no recorded last_fired (no proof of firing).
- **CROSS_DOMAIN_EVENT_CORRELATION** (FAIL): Event fixture:untracked-instance-001 compute.untracked_asset_created affected rogue-prod-worker-99; scanner_covered=False; alert_rule_enabled=False; linked_ticket=false.
- **CROSS_DOMAIN_EVENT_CORRELATION** (FAIL): Event fixture:logging-audit-denied-001 logging.audit_disabled affected unknown-asset; scanner_covered=False; alert_rule_enabled=True; linked_ticket=false.
- **CROSS_DOMAIN_EVENT_CORRELATION** (FAIL): Event fixture:identity-admin-role-001 identity.admin_role_granted affected unknown-asset; scanner_covered=False; alert_rule_enabled=True; linked_ticket=false.
- **CROSS_DOMAIN_EVENT_CORRELATION** (FAIL): Event /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0 network.public_admin_port_opened affected prod-api-01; scanner_covered=False; alert_rule_enabled=False; linked_ticket=false.
- **RA5_EXPLOITATION_REVIEW** (FAIL): High finding nessus-2026-0501-prod-api-01-87839 affects prod-api-01 but central audit ingestion is not active for that asset.
- **RA5_EXPLOITATION_REVIEW** (FAIL): High finding nessus-2026-0501-prod-api-01-87839 affects prod-api-01 but no linked exploitation-review ticket or artifact was found.
- **RA5_EXPLOITATION_REVIEW** (FAIL): Generated exploitation review queries for CVE-2026-00001 and prod-api-01.
- **CM3_CHANGE_EVIDENCE_LINKAGE** (FAIL): No ticket linked to event fixture:untracked-instance-001 compute.untracked_asset_created.
- **CM3_CHANGE_EVIDENCE_LINKAGE** (FAIL): No ticket linked to event fixture:logging-audit-denied-001 logging.audit_disabled.
- **CM3_CHANGE_EVIDENCE_LINKAGE** (FAIL): No ticket linked to event fixture:identity-admin-role-001 identity.admin_role_granted.
- **CM3_CHANGE_EVIDENCE_LINKAGE** (FAIL): No ticket linked to event /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0 network.public_admin_port_opened.
- **CM3_CHANGE_EVIDENCE_LINKAGE** (FAIL): Ticket VULN-9912 exists for prod-api-01 vulnerability but lacks SIA, testing evidence, deployment evidence, and verification evidence.

## Partial evaluations

*missing: no evaluations in this category.*

## Correlated risky events

A **correlated risky event** is a semantically typed signal listed in the scenario's `correlations.json`. Each row is checked against the same cross-domain expectations as the primary incident: authoritative inventory, scanner scope, active central logging, enabled alerts with recipients, and change or vulnerability linkage. Missing links are reported as gaps (FAIL/PARTIAL)—they are not treated as if evidence were present.

- Event `fixture:untracked-instance-001` **compute.untracked_asset_created** on `rogue-prod-worker-99` (from correlations.json).
- Event `fixture:logging-audit-denied-001` **logging.audit_disabled** on `None` (from correlations.json).
- Event `fixture:identity-admin-role-001` **identity.admin_role_granted** on `None` (from correlations.json).
- Event `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0` **network.public_admin_port_opened** on `prod-api-01` (from correlations.json).

## Control impact

- AC-17
- AC-2
- AC-2(1)
- AC-2(3)
- AC-2(4)
- AC-2(7)
- AC-3
- AC-4
- AC-5
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
- AU-9(2)
- CA-5
- CA-7
- CM-10
- CM-11
- CM-3
- CM-4
- CM-5
- CM-6
- CM-7
- CM-8
- CM-8(1)
- CM-8(3)
- IA-2
- IA-4
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
- SC-7
- SC-7(3)
- SC-7(4)
- SC-7(5)
- SI-2
- SI-3
- SI-4
- SI-4(1)
- SI-4(16)
- SI-4(4)

## Recommended remediation sequence

1. **CM8_INVENTORY_RECONCILIATION**: Update inventory.; Investigate rogue asset.; Add scanner/logging coverage if asset is in boundary.; Update Integrated Inventory Workbook (IIW) or authoritative CMDB to match discovered reality.; Investigate rogue assets absent from inventory; validate ownership and boundary placement.
2. **RA5_SCANNER_SCOPE_COVERAGE**: Add missing target to scanner scope.; Confirm credentialed scan configuration.; Export scanner target configuration as system-generated evidence.; Create POA&M if coverage cannot be fixed immediately.
3. **AU6_CENTRALIZED_LOG_COVERAGE**: Configure central log forwarding.; Provide local and central copy of same event.; Add source coverage dashboard/saved search.; Generate missing SIEM query.
4. **SI4_ALERT_INSTRUMENTATION**: Generate SPL/KQL/GCP/AWS query.; Add enabled alert.; Add recipient list.; Produce sample alert evidence.; Link alert to incident/change response workflow.
5. **CROSS_DOMAIN_EVENT_CORRELATION**: Map detections to CMDB/inventory identifiers.; Ensure scanner scope covers in-boundary assets.; Enable central audit ingestion for the affected asset.; Enable alert rules with recipients for the semantic type.; Open and link an incident or change ticket to the event or asset.
6. **RA5_EXPLOITATION_REVIEW**: Run the generated Splunk / KQL / GCP queries and attach exports to the vulnerability ticket.; Link a ticket to the finding (`linked_finding_ids`) and record verification evidence.; Set exploitation_review.log_review_performed (or review artifact URL) on the finding row.; Confirm central log sources for the asset are active and cover the review window.
7. **CM3_CHANGE_EVIDENCE_LINKAGE**: Create/link change ticket.; Add SIA.; Add test evidence.; Add approval.; Add deployment evidence.; Add verification scan evidence.

## Generated artifacts

- `eval_results.json` (machine-readable evaluations).
- `correlations.json` (present).
- `poam.csv` (rows generated this run, best-effort count: 9).
- `instrumentation_plan.md` (present).
- `evidence_graph.json` (nodes: 6, edges: 6).

---

## Detailed evaluation results

Per-evaluation evidence and gaps exactly as emitted by the evaluation engine.

#### CM8_INVENTORY_RECONCILIATION — **FAIL**

- Declared inventory contains duplicate name values; resolve naming collisions.
- Declared inventory lists the same asset_id on multiple rows — authoritative IIW conflict.
- Declared inventory record Production API (inv-prod-api-dupname) is in boundary but has no matching discovered cloud asset.
- Discovered asset rogue-prod-worker-99 is not present in declared inventory.
- Discovered production-class asset `rogue-prod-worker-99` is absent from authoritative inventory (rogue asset risk).
- Declared inventory record Production API (stale CMDB row) expected private IP 10.254.0.99 but discovered ['10.0.1.50'].
- **Gap:** Duplicate declared inventory names detected: ['production api'].; Duplicate declared asset_id values: ['prod-api-01'].; Declared inventory record Production API (inv-prod-api-dupname) is in boundary but has no matching discovered cloud asset.; Discovered asset rogue-prod-worker-99 is not present in declared inventory.; Declared inventory record Production API (stale CMDB row) expected private IP 10.254.0.99 but discovered ['10.0.1.50'].

#### RA5_SCANNER_SCOPE_COVERAGE — **FAIL**

- prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- prod-api-standby-02 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.
- Discovered production compute asset `prod-api-01` has no scanner target coverage (not explicitly exempt).
- Discovered production compute asset `rogue-prod-worker-99` has no scanner target coverage (not explicitly exempt).
- Scanner finding `nessus-2026-0501-prod-api-01-87839` (high) on asset `prod-api-01` contradicts missing scanner target coverage for that asset.
- **Gap:** prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.; prod-api-01 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.; prod-api-standby-02 is in declared inventory and scanner_required=true, but no scanner target covers asset_id/name/IP.; Discovered production compute asset `prod-api-01` has no scanner target coverage (not explicitly exempt).; Discovered production compute asset `rogue-prod-worker-99` has no scanner target coverage (not explicitly exempt).; Scanner finding `nessus-2026-0501-prod-api-01-87839` (high) on asset `prod-api-01` contradicts missing scanner target coverage for that asset.

#### AU6_CENTRALIZED_LOG_COVERAGE — **FAIL**

- prod-api-01 requires logging but has no active central log source.
- prod-api-01 requires logging but has no active central log source.
- Declared `Production API` requires logging but has no matching discovered asset to verify sources.
- prod-storage-01 requires logging but has no active central log source.
- Critical compute asset `prod-api-01` lacks an active central log source seen within the last 24h window.
- Critical compute asset `rogue-prod-worker-99` lacks an active central log source seen within the last 24h window.
- Cloud control plane log source is active.
- Central log source `ls-api-01` is stale beyond the 24h threshold for a required/high-sensitivity asset context.
- **Gap:** prod-api-01 requires logging but has no active central log source.; prod-api-01 requires logging but has no active central log source.; Declared `Production API` requires logging but has no matching discovered asset to verify sources.; prod-storage-01 requires logging but has no active central log source.; Critical compute asset `prod-api-01` lacks an active central log source seen within the last 24h window.; Critical compute asset `rogue-prod-worker-99` lacks an active central log source seen within the last 24h window.; Central log source `ls-api-01` is stale beyond the 24h threshold for a required/high-sensitivity asset context.

#### SI4_ALERT_INSTRUMENTATION — **FAIL**

- No enabled alert rule covers compute.untracked_asset_created.
- Alert rule AC-2 — IAM admin role / policy attachment covers identity.admin_role_granted and has recipients soc@example.com, iam-governance@example.com.
- Alert rule AU-12 — CloudTrail StopLogging / DeleteTrail attempts covers logging.audit_disabled and has recipients soc@example.com.
- Alert rules reference network.public_admin_port_opened but none are enabled with recipients.
- Alert rule `spl-ss-002` covers observed semantics ['logging.audit_disabled'] but has no sample_alert_ref and no recorded last_fired (no proof of firing).
- **Gap:** No enabled alert rule covers compute.untracked_asset_created.; Alert rules reference network.public_admin_port_opened but none are enabled with recipients.; Alert rule `spl-ss-002` covers observed semantics ['logging.audit_disabled'] but has no sample_alert_ref and no recorded last_fired (no proof of firing).

#### CROSS_DOMAIN_EVENT_CORRELATION — **FAIL**

- Event fixture:untracked-instance-001 compute.untracked_asset_created affected rogue-prod-worker-99; scanner_covered=False; alert_rule_enabled=False; linked_ticket=false.
- Event fixture:logging-audit-denied-001 logging.audit_disabled affected unknown-asset; scanner_covered=False; alert_rule_enabled=True; linked_ticket=false.
- Event fixture:identity-admin-role-001 identity.admin_role_granted affected unknown-asset; scanner_covered=False; alert_rule_enabled=True; linked_ticket=false.
- Event /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0 network.public_admin_port_opened affected prod-api-01; scanner_covered=False; alert_rule_enabled=False; linked_ticket=false.
- **Gap:** fixture:untracked-instance-001: missing required observability (alert_rule, central_logging).; fixture:logging-audit-denied-001: missing required observability (central_logging).; fixture:identity-admin-role-001: missing required observability (central_logging).; /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0: missing required observability (alert_rule, central_logging).

#### RA5_EXPLOITATION_REVIEW — **FAIL**

- High finding nessus-2026-0501-prod-api-01-87839 affects prod-api-01 but central audit ingestion is not active for that asset.
- High finding nessus-2026-0501-prod-api-01-87839 affects prod-api-01 but no linked exploitation-review ticket or artifact was found.
- Generated exploitation review queries for CVE-2026-00001 and prod-api-01.
- **Gap:** nessus-2026-0501-prod-api-01-87839: High/Critical finding on `prod-api-01` lacks active central log coverage for exploitation review.; nessus-2026-0501-prod-api-01-87839: missing exploitation review (ticket verification and/or finding review metadata).

#### CM3_CHANGE_EVIDENCE_LINKAGE — **FAIL**

- No ticket linked to event fixture:untracked-instance-001 compute.untracked_asset_created.
- No ticket linked to event fixture:logging-audit-denied-001 logging.audit_disabled.
- No ticket linked to event fixture:identity-admin-role-001 identity.admin_role_granted.
- No ticket linked to event /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0 network.public_admin_port_opened.
- Ticket VULN-9912 exists for prod-api-01 vulnerability but lacks SIA, testing evidence, deployment evidence, and verification evidence.
- **Gap:** No ticket linked to event fixture:untracked-instance-001 compute.untracked_asset_created.; No ticket linked to event fixture:logging-audit-denied-001 logging.audit_disabled.; No ticket linked to event fixture:identity-admin-role-001 identity.admin_role_granted.; No ticket linked to event /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0 network.public_admin_port_opened.; Ticket VULN-9912 exists for prod-api-01 vulnerability but lacks SIA, testing evidence, deployment evidence, and verification evidence.

#### CA5_POAM_STATUS — **OPEN**

- Added 7 POA&M row(s) for failing/partial evaluations (duplicates skipped: 0).
- CM8_INVENTORY_RECONCILIATION: FAIL
- RA5_SCANNER_SCOPE_COVERAGE: FAIL
- AU6_CENTRALIZED_LOG_COVERAGE: FAIL
- SI4_ALERT_INSTRUMENTATION: FAIL
- CROSS_DOMAIN_EVENT_CORRELATION: FAIL
- RA5_EXPLOITATION_REVIEW: FAIL
- CM3_CHANGE_EVIDENCE_LINKAGE: FAIL
- **Gap:** Continuous monitoring evidence incomplete; new POA&M rows written to poam.csv.
