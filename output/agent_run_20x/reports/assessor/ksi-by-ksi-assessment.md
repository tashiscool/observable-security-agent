# KSI-by-KSI assessment

**Audience:** 3PAO, FedRAMP reviewer, technical assessor.

**Package reconciliation parity:** `aligned` (machine vs. human manifest as recorded).

## Legend (how to read status vs. evidence)

- **Passed control/capability:** KSI rollup status PASS in this snapshot.
- **Failed capability:** KSI rollup FAIL, or linked evaluation outcome reflected as FAIL in rollup.
- **Missing evidence:** No artifact or registry linkage stated where one is required by policy; or finding text documents an evidence gap (quoted from findings, not invented here).
- **Manual evidence:** Catalog or criterion `validation_type` is manual/hybrid; assessor evidence is expected out-of-band.
- **Inherited responsibility:** Out-of-scope items in `authorization_scope` whose rationale states CSP or inherited boundaries.
- **Customer responsibility:** In-scope services/categories in `authorization_scope` and the logical system boundary.

## `KSI-IAM-01` — Centralized identity and account lifecycle management

- **Theme:** Identity and Access Management
- **Objective:** Demonstrate that identities and privileged access are provisioned, monitored, and deprovisioned in line with policy, with auditable approval and MFA posture.
- **Legacy Rev4 controls:** AC-2, AC-3, AC-5, IA-2, IA-4
- **Legacy Rev5 controls:** AC-2, AC-3, AC-5, IA-2, IA-4
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `identity_provider_users`: registry `automation_score`=4, `collection_method`=api
- `siem_alert_rule_export`: registry `automation_score`=4, `collection_method`=hybrid
- `incident_ticket_export`: registry `automation_score`=2, `collection_method`=file
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`IAM-CRI-001`** (hybrid): Privileged users must be approved through a documented workflow. — expected: Approvals recorded and retrievable for privileged role assignments.
  - Evidence required (ids): incident_ticket_export, cloud_control_plane_events
- **`IAM-CRI-002`** (automated): Privileged users must have MFA enforced where required by policy. — expected: MFA enforcement evidenced for privileged accounts in scope.
  - Evidence required (ids): siem_alert_rule_export, central_log_source_export
- **`IAM-CRI-003`** (hybrid): Terminated users must not retain active access to in-scope systems. — expected: No active sessions or credentials for terminated identities.
  - Evidence required (ids): identity_provider_users, cloud_asset_inventory, central_log_source_export
- **`IAM-CRI-004`** (manual): Break-glass accounts must be documented, monitored, and reviewed. — expected: Break-glass inventory, monitoring coverage, and periodic review artifacts.
  - Evidence required (ids): identity_provider_users, siem_alert_rule_export, incident_ticket_export

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_PERMISSION_SCOPE, AGENT_POLICY_VIOLATIONS, AGENT_TOOL_GOVERNANCE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_PERMISSION_SCOPE, AGENT_POLICY_VIOLATIONS, AGENT_TOOL_GOVERNANCE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-IAM-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-LOG-01` — Centralized logging and security monitoring

- **Theme:** Monitoring, Logging, and Auditing
- **Objective:** Demonstrate that security-relevant events are captured, forwarded to a central platform, protected in transit and at rest, and can drive accountable alerting.
- **Legacy Rev4 controls:** AU-2, AU-6, AU-8, AU-9, AU-12
- **Legacy Rev5 controls:** AU-2, AU-6, AU-8, AU-9, AU-12
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `central_log_source_export`: registry `automation_score`=4, `collection_method`=hybrid
- `siem_alert_rule_export`: registry `automation_score`=4, `collection_method`=hybrid
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`LOG-CRI-001`** (automated): Cloud control plane logs are enabled for in-scope accounts and regions. — expected: Control-plane log sources configured and active.
  - Evidence required (ids): central_log_source_export
  - Linked eval ids (catalog): AU6_CENTRALIZED_LOG_COVERAGE
- **`LOG-CRI-002`** (hybrid): Logs are centralized to the approved SIEM or log analytics service. — expected: Central ingestion paths documented with recent receipt evidence.
  - Evidence required (ids): central_log_source_export
  - Linked eval ids (catalog): AU6_CENTRALIZED_LOG_COVERAGE
- **`LOG-CRI-003`** (manual): Logs are encrypted and access-controlled per policy. — expected: Encryption and RBAC/retention settings evidenced for log stores.
  - Evidence required (ids): central_log_source_export
- **`LOG-CRI-004`** (hybrid): Security-relevant events are alertable with accountable routing. — expected: Enabled rules with recipients mapped to high-risk semantics.
  - Evidence required (ids): siem_alert_rule_export
  - Linked eval ids (catalog): SI4_ALERT_INSTRUMENTATION
- **`LOG-CRI-005`** (hybrid): Local-to-central evidence is available where required for AU reviews. — expected: Sample local and matching central events retrievable for sampled assets.
  - Evidence required (ids): central_log_source_export
  - Linked eval ids (catalog): AU6_CENTRALIZED_LOG_COVERAGE

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_AUDITABILITY, AGENT_MEMORY_CONTEXT_SAFETY, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_AUDITABILITY, AGENT_MEMORY_CONTEXT_SAFETY, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-LOG-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-VULN-01` — Vulnerability and configuration risk management

- **Theme:** Service Configuration
- **Objective:** Demonstrate vulnerability scanning scope, timely handling of findings, and exploitation-review discipline for high/critical issues aligned to inventory.
- **Legacy Rev4 controls:** RA-5, SI-2, SI-3
- **Legacy Rev5 controls:** RA-5, SI-2, SI-3
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `scanner_target_export`: registry `automation_score`=2, `collection_method`=file
- `vulnerability_scan_findings`: registry `automation_score`=4, `collection_method`=hybrid
- `declared_system_inventory`: registry `automation_score`=2, `collection_method`=file
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`VULN-CRI-001`** (automated): All in-scope assets are covered by an authorized scanner scope. — expected: Scanner targets reconcile to authoritative inventory for in-boundary assets.
  - Evidence required (ids): scanner_target_export, declared_system_inventory
  - Linked eval ids (catalog): RA5_SCANNER_SCOPE_COVERAGE, CM8_INVENTORY_RECONCILIATION
- **`VULN-CRI-002`** (hybrid): High/critical vulnerabilities meet SLA or have an approved exception on record. — expected: SLA tracking or formal risk acceptance linked to the finding.
  - Evidence required (ids): vulnerability_scan_findings, incident_ticket_export
- **`VULN-CRI-003`** (hybrid): Exploitation review is performed for high/critical vulnerabilities. — expected: Log review or ticket verification artifacts tied to qualifying findings.
  - Evidence required (ids): vulnerability_scan_findings, central_log_source_export, incident_ticket_export
  - Linked eval ids (catalog): RA5_EXPLOITATION_REVIEW
- **`VULN-CRI-004`** (automated): Scanner scope is system-generated and reconciled to inventory. — expected: Exportable target list with identifiers matching inventory keys.
  - Evidence required (ids): scanner_target_export, declared_system_inventory
  - Linked eval ids (catalog): RA5_SCANNER_SCOPE_COVERAGE, CM8_INVENTORY_RECONCILIATION

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_APPROVAL_GATES, CA5_POAM_STATUS, CM3_CHANGE_EVIDENCE_LINKAGE, CROSS_DOMAIN_EVENT_CORRELATION, RA5_EXPLOITATION_REVIEW, RA5_SCANNER_SCOPE_COVERAGE, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_APPROVAL_GATES, CA5_POAM_STATUS, CM3_CHANGE_EVIDENCE_LINKAGE, CROSS_DOMAIN_EVENT_CORRELATION, RA5_EXPLOITATION_REVIEW, RA5_SCANNER_SCOPE_COVERAGE, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-VULN-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-CM-01` — Controlled change and release discipline

- **Theme:** Change Management
- **Objective:** Demonstrate that material changes follow approved workflows with security analysis, testing, deployment, and verification evidence linked to records.
- **Legacy Rev4 controls:** CM-2, CM-3, CM-4, CM-5, CM-6, SI-2
- **Legacy Rev5 controls:** CM-2, CM-3, CM-4, CM-5, CM-6, SI-2
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `change_ticket_export`: registry `automation_score`=2, `collection_method`=file
- `cloud_control_plane_events`: registry `automation_score`=4, `collection_method`=hybrid
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`CM-CRI-001`** (hybrid): Risky changes have traceable tickets or equivalent change records. — expected: Change IDs linked to assets or events under assessment.
  - Evidence required (ids): change_ticket_export, cloud_control_plane_events
  - Linked eval ids (catalog): CM3_CHANGE_EVIDENCE_LINKAGE
- **`CM-CRI-002`** (manual): Change tickets include SIA, testing, approval, deployment, and verification evidence. — expected: Required CM-3 evidence flags satisfied or compensating artifacts attached.
  - Evidence required (ids): change_ticket_export
  - Linked eval ids (catalog): CM3_CHANGE_EVIDENCE_LINKAGE
- **`CM-CRI-003`** (hybrid): Deployment evidence links to the approved change record. — expected: Deployment timestamps or automation receipts tied to change ID.
  - Evidence required (ids): change_ticket_export
  - Linked eval ids (catalog): CM3_CHANGE_EVIDENCE_LINKAGE
- **`CM-CRI-004`** (hybrid): Configuration drift is detectable for critical service classes. — expected: Drift detection sources or periodic attestations on file.
  - Evidence required (ids): cloud_asset_inventory, correlation_assessment_export

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE, CA5_POAM_STATUS, CM3_CHANGE_EVIDENCE_LINKAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE, CA5_POAM_STATUS, CM3_CHANGE_EVIDENCE_LINKAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-CM-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-INV-01` — Authoritative inventory and boundary posture

- **Theme:** Policy and Inventory
- **Objective:** Demonstrate that declared inventory reconciles to discovery, includes required attributes, and surfaces duplicate, stale, or rogue assets for resolution.
- **Legacy Rev4 controls:** CM-8, PL-2, RA-2
- **Legacy Rev5 controls:** CM-8, PL-2, RA-2
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `declared_system_inventory`: registry `automation_score`=2, `collection_method`=file
- `cloud_asset_inventory`: registry `automation_score`=3, `collection_method`=hybrid
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`INV-CRI-001`** (automated): Discovered assets reconcile with declared authoritative inventory. — expected: No unresolved rogue production-class assets absent from inventory.
  - Evidence required (ids): declared_system_inventory, cloud_asset_inventory
  - Linked eval ids (catalog): CM8_INVENTORY_RECONCILIATION
- **`INV-CRI-002`** (hybrid): Inventory includes boundary status, owner, component type, and scanner/log requirements. — expected: Required columns populated for in-scope rows sampled by assessor.
  - Evidence required (ids): declared_system_inventory
  - Linked eval ids (catalog): CM8_INVENTORY_RECONCILIATION
- **`INV-CRI-003`** (automated): Duplicate, stale, or conflicting inventory rows are flagged and tracked. — expected: IIW/CMDB reconciliation process evidences collision handling.
  - Evidence required (ids): declared_system_inventory, cloud_asset_inventory
  - Linked eval ids (catalog): CM8_INVENTORY_RECONCILIATION

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: CM8_INVENTORY_RECONCILIATION, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** CM8_INVENTORY_RECONCILIATION, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-INV-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-IR-01` — Security incident readiness and traceable response

- **Theme:** Incident Response
- **Objective:** Demonstrate that suspicious and declared incidents have timelines, accountable actions, notifications, and closure aligned to monitoring signals.
- **Legacy Rev4 controls:** IR-4, IR-5, IR-6, SI-4
- **Legacy Rev5 controls:** IR-4, IR-5, IR-6, SI-4
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `siem_alert_rule_export`: registry `automation_score`=4, `collection_method`=hybrid
- `incident_ticket_export`: registry `automation_score`=2, `collection_method`=file
- `cloud_control_plane_events`: registry `automation_score`=4, `collection_method`=hybrid
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`IR-CRI-001`** (hybrid): Suspicious events have documented response evidence within policy timelines. — expected: Tickets or IR records with owner, timestamps, and disposition.
  - Evidence required (ids): incident_ticket_export, siem_alert_rule_export
  - Linked eval ids (catalog): CROSS_DOMAIN_EVENT_CORRELATION
- **`IR-CRI-002`** (manual): Incidents include event timeline, action log, notification, and closure evidence. — expected: Complete IR record set per agency IR plan.
  - Evidence required (ids): incident_ticket_export
- **`IR-CRI-003`** (hybrid): High-risk detections link to accountable tickets or cases. — expected: Correlation from alert to ticket ID for sampled high-risk semantics.
  - Evidence required (ids): siem_alert_rule_export, incident_ticket_export
  - Linked eval ids (catalog): CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_POLICY_VIOLATIONS, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_POLICY_VIOLATIONS, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No alert rules are defined while security-relevant semantic events require instrumentation.
- **`FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `logging.audit_disabled`. Observed gap: No enabled alert rule covers logging.audit_disabled.
- **`FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`** — severity `high` — POA&M: `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
  - Description (excerpt): No evidence was provided showing an enabled, accountable alert path exists for the assessed risk signal affecting `network.public_admin_port_opened`. Observed gap: No enabled alert rule covers network.public_admin_port_opened.
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`, `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-IR-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-REC-01` — Backup, recovery, and continuity evidence

- **Theme:** Recovery Planning
- **Objective:** Demonstrate backups for critical assets, encryption, tested restores, and documented RTO/RPO commitments.
- **Legacy Rev4 controls:** CP-9, CP-10
- **Legacy Rev5 controls:** CP-9, CP-10
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: False
- `backup_configuration_export`: registry `automation_score`=2, `collection_method`=file
- `cloud_asset_inventory`: registry `automation_score`=3, `collection_method`=hybrid
- `restore_test_records`: registry `automation_score`=1, `collection_method`=manual

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`REC-CRI-001`** (manual): Critical assets have backups meeting policy frequency and retention. — expected: Backup policy excerpts plus scope list for critical assets.
  - Evidence required (ids): cloud_asset_inventory
- **`REC-CRI-002`** (manual): Backups are encrypted and access-controlled. — expected: Encryption and key management references for backup stores.
  - Evidence required (ids): backup_configuration_export
- **`REC-CRI-003`** (manual): Restore tests are documented with outcomes. — expected: Test reports or tickets with pass/fail and follow-up actions.
  - Evidence required (ids): restore_test_records
- **`REC-CRI-004`** (manual): RTO/RPO evidence exists for prioritized workloads. — expected: BIA or service catalog fields mapping workloads to RTO/RPO.
  - Evidence required (ids): declared_system_inventory

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: CA5_POAM_STATUS, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** CA5_POAM_STATUS, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-REC-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-SCRM-01` — Supply chain and third-party dependency transparency

- **Theme:** Supply Chain Risk
- **Objective:** Demonstrate vendor and dependency visibility, inheritance mapping for external services, SBOM or equivalent tracking, and oversight of critical suppliers.
- **Legacy Rev4 controls:** SA-4, SA-8, SA-9, SA-11
- **Legacy Rev5 controls:** SA-4, SA-8, SA-9, SA-11, SR-3, SR-5
- **Validation mode (catalog):** `manual`

### Automation and evidence sources

Catalog `automation_target`: False
- `vendor_inventory`: registry `automation_score`=1, `collection_method`=manual
- `incident_ticket_export`: registry `automation_score`=2, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`SCRM-CRI-001`** (manual): Vendor inventory exists for in-scope external services and software. — expected: Register of vendors with service descriptions and data sensitivity.
  - Evidence required (ids): vendor_inventory
- **`SCRM-CRI-002`** (manual): External services are mapped to authorization boundary and inheritance statements. — expected: SSP or annex tables linking CSP services to inherited controls.
  - Evidence required (ids): vendor_inventory
- **`SCRM-CRI-003`** (hybrid): Dependencies or SBOM artifacts are tracked for critical workloads. — expected: SBOM storage location and refresh cadence documented.
  - Evidence required (ids): sbom_export
- **`SCRM-CRI-004`** (manual): Critical supplier risks are tracked with mitigation owners. — expected: Risk register entries or POA&M rows for supplier issues.
  - Evidence required (ids): incident_ticket_export

### KSI validation row (machine-readable)

- **Status:** `PASS`
- **Summary:** Rolled up from evaluations: AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE, CROSS_DOMAIN_EVENT_CORRELATION (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE, CROSS_DOMAIN_EVENT_CORRELATION
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- *None linked by `linked_ksi_ids` / `ksi_ids` in this package.*

### POA&M references (by KSI linkage)

- *None via `source_ksi_ids`; see finding-level POA&M above if applicable.*

### Assessor conclusion (evidence-bounded)

KSI rollup status is PASS in this package snapshot. Conclusion is limited to the evaluations and artifacts referenced in machine-readable fields.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-SCRM-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-AGENT-01` — AI agent identities are registered, scoped, and monitored

- **Theme:** Identity and Access Management
- **Objective:** Demonstrate that every in-scope AI agent has a registered identity, accountable owner and purpose, explicit allowed data/tool scopes, approval-backed privileged actions, and credential posture that does not share secrets with human operators.
- **Legacy Rev4 controls:** AC-2, AC-3, AC-6, IA-2, IA-4
- **Legacy Rev5 controls:** AC-2, AC-3, AC-6, IA-2, IA-4
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `agent_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `identity_provider_users`: registry `automation_score`=4, `collection_method`=api

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`AGENT-IAM-CRI-001`** (hybrid): Every agent has a registered identity with stable agent_id in telemetry. — expected: agent_identities.json (or package slice) lists each agent with required attributes.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_PERMISSION_SCOPE
- **`AGENT-IAM-CRI-002`** (hybrid): Every agent has documented owner and purpose fields. — expected: Ownership and purpose recorded per agent identity row.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_PERMISSION_SCOPE
- **`AGENT-IAM-CRI-003`** (hybrid): Every agent has explicit allowed scopes for tools and data. — expected: Allow lists and data scopes are present and enforced in policy checks.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_TOOL_GOVERNANCE, AGENT_PERMISSION_SCOPE
- **`AGENT-IAM-CRI-004`** (hybrid): Privileged or high-risk agent actions require recorded approvals. — expected: Approval metadata present on qualifying tool_calls rows.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_APPROVAL_GATES
- **`AGENT-IAM-CRI-005`** (hybrid): Agent credentials are not shared with human operators (no shared long-lived secrets). — expected: Identity and tool_call records show non-human scoped credentials only.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_PERMISSION_SCOPE

### KSI validation row (machine-readable)

- **Status:** `PASS`
- **Summary:** Rolled up from evaluations: AGENT_APPROVAL_GATES, AGENT_PERMISSION_SCOPE (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_APPROVAL_GATES, AGENT_PERMISSION_SCOPE
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- *None linked by `linked_ksi_ids` / `ksi_ids` in this package.*

### POA&M references (by KSI linkage)

- *None via `source_ksi_ids`; see finding-level POA&M above if applicable.*

### Assessor conclusion (evidence-bounded)

KSI rollup status is PASS in this package snapshot. Conclusion is limited to the evaluations and artifacts referenced in machine-readable fields.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-AGENT-01` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-AGENT-02` — Agent decisions and tool use are logged and reviewable

- **Theme:** Monitoring, Logging, and Auditing
- **Objective:** Demonstrate that agent tool invocations policy decisions approvals memory or context access and high-risk behaviors are logged centrally and reviewable with accountable alerting where required.
- **Legacy Rev4 controls:** AU-2, AU-6, AU-12, SI-4
- **Legacy Rev5 controls:** AU-2, AU-6, AU-12, SI-4
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `agent_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `central_log_source_export`: registry `automation_score`=4, `collection_method`=hybrid
- `siem_alert_rule_export`: registry `automation_score`=4, `collection_method`=hybrid
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`AGENT-LOG-CRI-001`** (hybrid): Tool calls are logged with agent identity raw_ref and policy decision fields. — expected: tool_calls[] entries are complete for replay.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_AUDITABILITY, AGENT_TOOL_GOVERNANCE
- **`AGENT-LOG-CRI-002`** (hybrid): Policy decisions for agent actions are logged and attributable. — expected: policy_decision captured on tool_calls or companion audit stream.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_AUDITABILITY
- **`AGENT-LOG-CRI-003`** (hybrid): Approval decisions for gated actions are logged. — expected: approval_required rows include status and approver reference when executed.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_APPROVAL_GATES
- **`AGENT-LOG-CRI-004`** (hybrid): Memory and external context access events are logged and labeled. — expected: memory_events[] with classification for sensitive writes.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_MEMORY_CONTEXT_SAFETY
- **`AGENT-LOG-CRI-005`** (hybrid): Alerts exist for high-risk agent behavior semantics per SOC policy. — expected: Mapped SIEM rules or tickets for agent high-risk semantics.
  - Evidence required (ids): siem_alert_rule_export, correlation_assessment_export
  - Linked eval ids (catalog): AGENT_POLICY_VIOLATIONS

### KSI validation row (machine-readable)

- **Status:** `FAIL`
- **Summary:** Rolled up from evaluations: AGENT_AUDITABILITY, AGENT_MEMORY_CONTEXT_SAFETY, AGENT_TOOL_GOVERNANCE, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_AUDITABILITY, AGENT_MEMORY_CONTEXT_SAFETY, AGENT_TOOL_GOVERNANCE, AU6_CENTRALIZED_LOG_COVERAGE, CROSS_DOMAIN_EVENT_CORRELATION, TRACKER_EVIDENCE_GAP_ANALYSIS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `3`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `5`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `4`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `2`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0010-deviation-request-missing [moderate/deviation_request_missing] row=10 controls=CA-5 poam_required=yes :: Deviation request missing: POA&M updates: Provide the current POA&M with deviati
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **`FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`** — severity `critical` — POA&M: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
  - Description (excerpt): Evidence deficiency noted for evaluation `TRACKER_EVIDENCE_GAP_ANALYSIS` affecting `1`: the assessment did not receive substantiating artifacts for this gap. Observed gap: gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram

### POA&M references (by KSI linkage)

POA&M ids tied to this KSI via `source_ksi_ids`: `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`, `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`

### Assessor conclusion (evidence-bounded)

KSI rollup status is FAIL. Conclusion: treat as open work until linked findings and POA&M disposition are closed or formally risk-accepted per program policy.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-AGENT-02` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-AGENT-03` — Agentic misuse is detectable and actionable

- **Theme:** Incident Response
- **Objective:** Demonstrate detection and response for prompt injection unauthorized tool use compromised-agent hypotheses with threat-hunt timelines and containment guidance documented.
- **Legacy Rev4 controls:** IR-4, IR-5, IR-6, SI-4
- **Legacy Rev5 controls:** IR-4, IR-5, IR-6, SI-4
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `agent_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `incident_ticket_export`: registry `automation_score`=2, `collection_method`=file
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `siem_alert_rule_export`: registry `automation_score`=4, `collection_method`=hybrid

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`AGENT-IR-CRI-001`** (hybrid): Prompt injection or adversarial prompt detections are tracked with evidence. — expected: Detections or policy_violations rows cite injection-class events.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_POLICY_VIOLATIONS
- **`AGENT-IR-CRI-002`** (hybrid): Unauthorized tool use creates a security finding and accountable ticket path. — expected: Violations linked to tickets or IR cases where required.
  - Evidence required (ids): agent_assessment_export, incident_ticket_export
  - Linked eval ids (catalog): AGENT_POLICY_VIOLATIONS, AGENT_TOOL_GOVERNANCE
- **`AGENT-IR-CRI-003`** (hybrid): Compromised-agent hypotheses produce a documented threat-hunt timeline. — expected: Threat hunt output references agent_id and hypothesis identifiers.
  - Evidence required (ids): correlation_assessment_export
  - Linked eval ids (catalog): AGENT_POLICY_VIOLATIONS
- **`AGENT-IR-CRI-004`** (manual): Containment guidance exists for high-severity agent incidents. — expected: Runbook or IR plan excerpt covering agent isolation and credential rotation.
  - Evidence required (ids): incident_ticket_export

### KSI validation row (machine-readable)

- **Status:** `PASS`
- **Summary:** Rolled up from evaluations: AGENT_POLICY_VIOLATIONS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_POLICY_VIOLATIONS
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- *None linked by `linked_ksi_ids` / `ksi_ids` in this package.*

### POA&M references (by KSI linkage)

- *None via `source_ksi_ids`; see finding-level POA&M above if applicable.*

### Assessor conclusion (evidence-bounded)

KSI rollup status is PASS in this package snapshot. Conclusion is limited to the evaluations and artifacts referenced in machine-readable fields.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-AGENT-03` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---

## `KSI-AGENT-04` — Agent tools and permissions are governed as system changes

- **Theme:** Change Management
- **Objective:** Demonstrate that new tools permission changes prompts and policies are versioned approved and backed by review evidence consistent with CM and SA families.
- **Legacy Rev4 controls:** CM-3, CM-5, CM-6, SA-10
- **Legacy Rev5 controls:** CM-3, CM-5, CM-6, SA-10
- **Validation mode (catalog):** `hybrid`

### Automation and evidence sources

Catalog `automation_target`: True
- `agent_assessment_export`: registry `automation_score`=3, `collection_method`=file
- `change_ticket_export`: registry `automation_score`=2, `collection_method`=file
- `correlation_assessment_export`: registry `automation_score`=3, `collection_method`=file

### Pass/fail criteria (catalog)

Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.

- **`AGENT-CM-CRI-001`** (hybrid): New or expanded agent tools require documented approval before production use. — expected: Tool registration or change record ties tool_name to approver evidence.
  - Evidence required (ids): agent_assessment_export, change_ticket_export
  - Linked eval ids (catalog): AGENT_TOOL_GOVERNANCE, AGENT_APPROVAL_GATES
- **`AGENT-CM-CRI-002`** (hybrid): Tool permission changes are ticketed and traceable. — expected: CM-3 style linkage between permission deltas and tickets.
  - Evidence required (ids): change_ticket_export, agent_assessment_export
  - Linked eval ids (catalog): AGENT_APPROVAL_GATES
- **`AGENT-CM-CRI-003`** (hybrid): Prompts and agent policies are versioned with history. — expected: Version identifiers or commit refs for prompts/policies in evidence bundle.
  - Evidence required (ids): agent_assessment_export
  - Linked eval ids (catalog): AGENT_TOOL_GOVERNANCE
- **`AGENT-CM-CRI-004`** (manual): Material policy changes include review evidence (peer or CAB). — expected: Reviewer sign-off or ticket attachment for policy change window.
  - Evidence required (ids): incident_ticket_export, change_ticket_export
  - Linked eval ids (catalog): AGENT_APPROVAL_GATES

### KSI validation row (machine-readable)

- **Status:** `PASS`
- **Summary:** Rolled up from evaluations: AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).
- **Linked evaluation ids:** AGENT_APPROVAL_GATES, AGENT_TOOL_GOVERNANCE
- **Evidence refs (structured):** `[{"evidence_id": "EV-1BC6343FE36EC1D07370", "role": "primary", "json_pointer": "#/evaluations", "artifact": "eval_results.json"}]`

### Findings linked to this KSI

- *None linked by `linked_ksi_ids` / `ksi_ids` in this package.*

### POA&M references (by KSI linkage)

- *None via `source_ksi_ids`; see finding-level POA&M above if applicable.*

### Assessor conclusion (evidence-bounded)

KSI rollup status is PASS in this package snapshot. Conclusion is limited to the evaluations and artifacts referenced in machine-readable fields.

**Machine-readable path:** `fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `KSI-AGENT-04` (array order is not guaranteed to match catalog order).
**Reconciliation status (package-level):** `aligned`

---
