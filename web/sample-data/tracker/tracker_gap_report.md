# Tracker Evidence Gap Analysis

- Eval ID: `TRACKER_EVIDENCE_GAP_ANALYSIS`
- Result: **FAIL**
- Severity: `critical`
- Open evidence gaps: 15
- High/Critical gaps: 14
- Gaps requiring POA&M: 10
- Informational tracker items: 1

## Summary

14 of 15 open evidence gap(s) are high/critical severity. 10 require POA&M.

## Group breakdown

### Inventory reconciliation (CM-8 family)

- Group key: `inventory`
- Open gaps: **2**
- Max severity: `high`
- POA&M required: **no**
- Controls impacted: `CM-8`, `CM-8(1)`, `CM-8(3)`, `CA-7`
- Linked KSI IDs: `KSI-INV-01`
- Gap types observed: `inventory_mismatch`
- Tracker rows: `1`, `2`
- Recommended closure artifacts:
  - declared_inventory.csv reconciled against discovered_assets.json

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0001-inventory-mismatch` | `1` | high | inventory_mismatch | CM-8, CM-8(1), CM-8(3) | Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus an authoritative AWS account dump (EC2, RDS, ELB/ALB, S3, VP |
| `gap-0002-inventory-mismatch` | `2` | high | inventory_mismatch | CM-8, CA-7 | Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets including IP ranges and public-exposure flag. |

### Scanner scope and vulnerability evidence (RA-5 family)

- Group key: `scanner_vulnerability`
- Open gaps: **3**
- Max severity: `critical`
- POA&M required: **yes**
- Controls impacted: `RA-5`, `RA-5(3)`, `RA-5(5)`, `SI-2`, `RA-5(8)`
- Linked KSI IDs: `KSI-VULN-01`, `KSI-IR-01`
- Gap types observed: `credentialed_scan_evidence_missing`, `vulnerability_scan_evidence_missing`, `exploitation_review_missing`
- Tracker rows: `3`, `4`, `5`
- Recommended closure artifacts:
  - scanner_targets.csv with credentialed=true + plugin/profile evidence
  - scanner_findings.json export from latest credentialed scan
  - scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0003-credentialed-scan-evidence-missing` | `3` | high | credentialed_scan_evidence_missing | RA-5, RA-5(3), RA-5(5) | Credentialed scan evidence missing: Provide the Nessus scan target list and credentialed-scan profile evidence for the boundary; show that all in-boundary a |
| `gap-0004-vulnerability-scan-evidence-missing` | `4` | high | vulnerability_scan_evidence_missing | RA-5, SI-2 | Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (full scope) plus Burp web-app scan signatures and any deltas vs. prior cycle. |
| `gap-0005-exploitation-review-missing` | `5` | critical | exploitation_review_missing | RA-5(8) | Exploitation review missing: Exploitation review for all High/Critical vulnerabilities open >30 days. Show IoC search and historical audit log review |

### Centralized logging and local-to-central correlation (AU family)

- Group key: `logging`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **yes**
- Controls impacted: `AU-2`, `AU-3`, `AU-6`, `AU-12`
- Linked KSI IDs: `KSI-LOG-01`
- Gap types observed: `local_to_central_log_correlation_missing`
- Tracker rows: `6`
- Recommended closure artifacts:
  - central_log_sources.json plus a local audit log sample correlated with the central index

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0006-local-to-central-log-correlation-missing` | `6` | high | local_to_central_log_correlation_missing | AU-2, AU-3, AU-6, AU-12 | Local to central log correlation missing: Demonstrate centralized audit log aggregation: provide Splunk dashboards/searches showing CloudTrail, VPC Flow Logs, Clo |

### Alert rules, samples, and response actions (SI-4 / IR family)

- Group key: `alerting`
- Open gaps: **3**
- Max severity: `high`
- POA&M required: **yes**
- Controls impacted: `AU-6`, `SI-4`, `SI-4(1)`, `SI-4(4)`, `IR-4`, `IR-6`
- Linked KSI IDs: `KSI-LOG-01`, `KSI-IR-01`
- Gap types observed: `alert_sample_missing`, `response_action_missing`
- Tracker rows: `7`, `8`, `11`
- Recommended closure artifacts:
  - sample_alert_ref pointing at an executed alert export
  - tickets.json entry citing the alert with documented response

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0007-alert-sample-missing` | `7` | high | alert_sample_missing | AU-6, SI-4 | Alert sample missing: Provide the alert rules / saved searches with recipient lists (SOC, IR, IAM Governance) and at least one example alert t |
| `gap-0008-response-action-missing` | `8` | high | response_action_missing | SI-4(1), SI-4(4) | Response action missing: List CloudWatch alarms and GuardDuty findings considered "suspicious activity"; map each to a documented response action |
| `gap-0011-response-action-missing` | `11` | high | response_action_missing | IR-4, IR-6 | Response action missing: Incident response evidence: any suspected or confirmed incidents in the past 12 months, including US-CERT/CISA notificat |

### Change evidence chain — SIA, testing, approval, deploy, verify (CM family)

- Group key: `change_management`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **yes**
- Controls impacted: `CM-3`, `SI-2`
- Linked KSI IDs: `KSI-CM-01`
- Gap types observed: `sia_missing`
- Tracker rows: `9`
- Recommended closure artifacts:
  - tickets.json field security_impact_analysis=true with SIA attachment

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0009-sia-missing` | `9` | high | sia_missing | CM-3, SI-2 | Sia missing: Sample change tickets in JIRA with full evidence chain: Security Impact Analysis, testing artifacts, CAB approval, deplo |

### Incident response evidence and US-CERT/CISA notifications (IR family)

- Group key: `incident_response`
- Open gaps: **2**
- Max severity: `high`
- POA&M required: **yes**
- Controls impacted: `SI-4(1)`, `SI-4(4)`, `IR-4`, `IR-6`
- Linked KSI IDs: `KSI-IR-01`
- Gap types observed: `response_action_missing`
- Tracker rows: `8`, `11`
- Recommended closure artifacts:
  - tickets.json entry citing the alert with documented response

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0008-response-action-missing` | `8` | high | response_action_missing | SI-4(1), SI-4(4) | Response action missing: List CloudWatch alarms and GuardDuty findings considered "suspicious activity"; map each to a documented response action |
| `gap-0011-response-action-missing` | `11` | high | response_action_missing | IR-4, IR-6 | Response action missing: Incident response evidence: any suspected or confirmed incidents in the past 12 months, including US-CERT/CISA notificat |

### POA&M updates and deviation requests (CA-5)

- Group key: `poam`
- Open gaps: **1**
- Max severity: `moderate`
- POA&M required: **yes**
- Controls impacted: `CA-5`
- Linked KSI IDs: `KSI-VULN-01`
- Gap types observed: `poam_update_missing`
- Tracker rows: `10`
- Recommended closure artifacts:
  - poam.csv with current status, dates, and milestones

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0010-poam-update-missing` | `10` | moderate | poam_update_missing | CA-5 | Poam update missing: POA&M updates: Provide the current POA&M with deviation requests, vendor dependencies, and operational requirements clea |

### Backup execution and restore-test evidence (CP-9 / CP-10)

- Group key: `recovery`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **yes**
- Controls impacted: `CP-9`, `CP-10`
- Linked KSI IDs: `KSI-REC-01`
- Gap types observed: `restore_test_missing`
- Tracker rows: `13`
- Recommended closure artifacts:
  - restore_tests.json with measured RTO/RPO

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0013-restore-test-missing` | `13` | high | restore_test_missing | CP-9, CP-10 | Restore test missing: Backup and recovery evidence: most recent restore test (RTO/RPO measurements) and snapshot evidence for RDS + AMI snapsh |

### Identity listings, MFA, access reviews, password policy (AC / IA)

- Group key: `identity_access`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **no**
- Controls impacted: `AC-2`, `AC-2(7)`, `AC-6`
- Linked KSI IDs: `KSI-IAM-01`
- Gap types observed: `identity_listing_missing`
- Tracker rows: `14`
- Recommended closure artifacts:
  - identity_users.json + privileged-account flag + MFA report

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0014-identity-listing-missing` | `14` | high | identity_listing_missing | AC-2, AC-2(7), AC-6 | Identity listing missing: Account listings: full IAM user list with privileged-account tagging, MFA report, and most recent quarterly access revie |

### FIPS-140 cryptography and key/cipher evidence (SC-12 / SC-13 / SC-28)

- Group key: `crypto`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **no**
- Controls impacted: `SC-13`, `SC-28`, `SC-12`
- Linked KSI IDs: `KSI-LOG-01`
- Gap types observed: `crypto_fips_evidence_missing`
- Tracker rows: `12`
- Recommended closure artifacts:
  - FIPS 140-2/3 module list + KMS rotation export + cipher policy

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0012-crypto-fips-evidence-missing` | `12` | high | crypto_fips_evidence_missing | SC-13, SC-28, SC-12 | Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use (AWS KMS, ALB ciphers, RDS encryption-at-rest), cipher list, and key r |

### Traffic flow / boundary / security group evidence (SC-7)

- Group key: `network_boundary`
- Open gaps: **1**
- Max severity: `high`
- POA&M required: **no**
- Controls impacted: `SC-7`, `SC-7(11)`
- Linked KSI IDs: `KSI-INV-01`
- Gap types observed: `traffic_flow_policy_missing`
- Tracker rows: `15`
- Recommended closure artifacts:
  - data-flow diagram + security_group inventory + ports/protocols matrix

| Gap ID | Source row | Severity | Gap type | Controls | Title |
|---|---|---|---|---|---|
| `gap-0015-traffic-flow-policy-missing` | `15` | high | traffic_flow_policy_missing | SC-7, SC-7(11) | Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram, security group inventory with ingress/egress rules, and the ports-a |

## Recommended closure actions

- inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json; close 2 gap(s); linked KSIs: KSI-INV-01.
- scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence; scanner_findings.json export from latest credentialed scan; scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true; close 3 gap(s); linked KSIs: KSI-VULN-01, KSI-IR-01.
- logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index; close 1 gap(s); linked KSIs: KSI-LOG-01.
- alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export; tickets.json entry citing the alert with documented response; close 3 gap(s); linked KSIs: KSI-LOG-01, KSI-IR-01.
- change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment; close 1 gap(s); linked KSIs: KSI-CM-01.
- incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response; close 2 gap(s); linked KSIs: KSI-IR-01.
- poam (CA-5): produce poam.csv with current status, dates, and milestones; close 1 gap(s); linked KSIs: KSI-VULN-01.
- recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO; close 1 gap(s); linked KSIs: KSI-REC-01.
- identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report; close 1 gap(s); linked KSIs: KSI-IAM-01.
- crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy; close 1 gap(s); linked KSIs: KSI-LOG-01.
- network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix; close 1 gap(s); linked KSIs: KSI-INV-01.

## All open evidence gaps

- gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- gap-0010-poam-update-missing [moderate/poam_update_missing] row=10 controls=CA-5 poam_required=yes :: Poam update missing: POA&M updates: Provide the current POA&M with deviation req
- gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram
