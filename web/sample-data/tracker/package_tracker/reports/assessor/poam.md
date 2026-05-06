# Plan of Action and Milestones (POA&M)

Generated from open assessment findings (FedRAMP 20x-style machine fields).

| POA&M ID | Finding (title) | Severity | Target completion | Status |
| --- | --- | --- | --- | --- |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417` | SI-4 Alert Instrumentation Coverage | high | 2026-06-05 | Open |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6` | SI-4 Alert Instrumentation Coverage | high | 2026-06-05 | Open |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8` | SI-4 Alert Instrumentation Coverage | high | 2026-06-05 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-B89FA44F2251` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` | Tracker Evidence Gap Analysis | critical | 2026-05-21 | Open |

## Remediation plans

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Priority / effort:** critical / 1-3 days
- **Current state:** No alert rules are defined while security-relevant semantic events require instrumentation.
- **Target state:** Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): Generate SPL/KQL/GCP/AWS query.
2. **2026-05-11** (Example Chief Risk Officer (delegate)): Add enabled alert.
3. **2026-05-17** (Example Chief Risk Officer (delegate)): Add recipient list.
4. **2026-05-23** (Example Chief Risk Officer (delegate)): Produce sample alert evidence.
5. **2026-05-29** (Example Chief Risk Officer (delegate)): Link alert to incident/change response workflow.
6. **2026-06-05** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Priority / effort:** critical / 1-3 days
- **Current state:** No enabled alert rule covers logging.audit_disabled.
- **Target state:** Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): Generate SPL/KQL/GCP/AWS query.
2. **2026-05-11** (Example Chief Risk Officer (delegate)): Add enabled alert.
3. **2026-05-17** (Example Chief Risk Officer (delegate)): Add recipient list.
4. **2026-05-23** (Example Chief Risk Officer (delegate)): Produce sample alert evidence.
5. **2026-05-29** (Example Chief Risk Officer (delegate)): Link alert to incident/change response workflow.
6. **2026-06-05** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Priority / effort:** critical / 1-3 days
- **Current state:** No enabled alert rule covers network.public_admin_port_opened.
- **Target state:** Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): Generate SPL/KQL/GCP/AWS query.
2. **2026-05-11** (Example Chief Risk Officer (delegate)): Add enabled alert.
3. **2026-05-17** (Example Chief Risk Officer (delegate)): Add recipient list.
4. **2026-05-23** (Example Chief Risk Officer (delegate)): Produce sample alert evidence.
5. **2026-05-29** (Example Chief Risk Officer (delegate)): Link alert to incident/change response workflow.
6. **2026-06-05** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0001-inventory-mismatch [high/inventory_mismatch] row=1 controls=CM-8,CM-8(1),CM-8(3) poam_required=no :: Inventory mismatch: Provide the latest Integrated Inventory Workbook (IIW) plus
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0002-inventory-mismatch [high/inventory_mismatch] row=2 controls=CM-8,CA-7 poam_required=no :: Inventory mismatch: Inventory of Load Balancers (ALB/NLB) and S3 buckets includi
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0003-credentialed-scan-evidence-missing [high/credentialed_scan_evidence_missing] row=3 controls=RA-5,RA-5(3),RA-5(5) poam_required=yes :: Credentialed scan evidence missing: Provide the Nessus scan target list and cred
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0004-vulnerability-scan-evidence-missing [high/vulnerability_scan_evidence_missing] row=4 controls=RA-5,SI-2 poam_required=yes :: Vulnerability scan evidence missing: Latest Nessus vulnerability scan reports (f
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0005-exploitation-review-missing [critical/exploitation_review_missing] row=5 controls=RA-5(8) poam_required=yes :: Exploitation review missing: Exploitation review for all High/Critical vulnerabi
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0006-local-to-central-log-correlation-missing [high/local_to_central_log_correlation_missing] row=6 controls=AU-2,AU-3,AU-6,AU-12 poam_required=yes :: Local to central log correlation missing: Demonstrate centralized audit log aggr
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0007-alert-sample-missing [high/alert_sample_missing] row=7 controls=AU-6,SI-4 poam_required=yes :: Alert sample missing: Provide the alert rules / saved searches with recipient li
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0008-response-action-missing [high/response_action_missing] row=8 controls=SI-4(1),SI-4(4) poam_required=yes :: Response action missing: List CloudWatch alarms and GuardDuty findings considere
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0009-sia-missing [high/sia_missing] row=9 controls=CM-3,SI-2 poam_required=yes :: Sia missing: Sample change tickets in JIRA with full evidence chain: Security Im
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-B89FA44F2251` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-B89FA44F2251`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0010-poam-update-missing [moderate/poam_update_missing] row=10 controls=CA-5 poam_required=yes :: Poam update missing: POA&M updates: Provide the current POA&M with deviation req
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0011-response-action-missing [high/response_action_missing] row=11 controls=IR-4,IR-6 poam_required=yes :: Response action missing: Incident response evidence: any suspected or confirmed
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0012-crypto-fips-evidence-missing [high/crypto_fips_evidence_missing] row=12 controls=SC-13,SC-28,SC-12 poam_required=no :: Crypto fips evidence missing: FIPS 140-2/3 evidence: list crypto modules in use
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0013-restore-test-missing [high/restore_test_missing] row=13 controls=CP-9,CP-10 poam_required=yes :: Restore test missing: Backup and recovery evidence: most recent restore test (RT
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0014-identity-listing-missing [high/identity_listing_missing] row=14 controls=AC-2,AC-2(7),AC-6 poam_required=no :: Identity listing missing: Account listings: full IAM user list with privileged-a
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.

### `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` — Tracker Evidence Gap Analysis

- **Finding ID:** `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`
- **Controls:** AC-2, AC-2(7), AC-6, AU-12, AU-2, AU-3, AU-6, CA-5, CA-7, CM-10, CM-11, CM-3, CM-8, CP-10, CP-9, IA-5, IR-4, IR-6, RA-5, RA-5(3), RA-5(5), RA-5(8), SC-12, SC-13, SC-28, SC-7, SC-7(11), SI-2, SI-4
- **KSIs:** KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01
- **Priority / effort:** moderate / 1-3 days
- **Current state:** gap-0015-traffic-flow-policy-missing [high/traffic_flow_policy_missing] row=15 controls=SC-7,SC-7(11) poam_required=no :: Traffic flow policy missing: Traffic flow / boundary evidence: data flow diagram
- **Target state:** Evidence is complete, linked to the assessed population, and retestable by an assessor sample.
- **Customer impact:** Potential for severe service disruption, data exposure, or regulatory breach until remediated.
- **Validation for closure:** True

1. **2026-05-06** (Example Chief Risk Officer (delegate)): inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json
2. **2026-05-06** (Example Chief Risk Officer (delegate)): close 2 gap(s)
3. **2026-05-06** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
4. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence
5. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json export from latest credentialed scan
6. **2026-05-07** (Example Chief Risk Officer (delegate)): scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true
7. **2026-05-08** (Example Chief Risk Officer (delegate)): close 3 gap(s)
8. **2026-05-08** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01, KSI-IR-01.
9. **2026-05-09** (Example Chief Risk Officer (delegate)): logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index
10. **2026-05-09** (Example Chief Risk Officer (delegate)): close 1 gap(s)
11. **2026-05-09** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
12. **2026-05-10** (Example Chief Risk Officer (delegate)): alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export
13. **2026-05-10** (Example Chief Risk Officer (delegate)): tickets.json entry citing the alert with documented response
14. **2026-05-11** (Example Chief Risk Officer (delegate)): close 3 gap(s)
15. **2026-05-11** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01, KSI-IR-01.
16. **2026-05-11** (Example Chief Risk Officer (delegate)): change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment
17. **2026-05-12** (Example Chief Risk Officer (delegate)): close 1 gap(s)
18. **2026-05-12** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-CM-01.
19. **2026-05-13** (Example Chief Risk Officer (delegate)): incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response
20. **2026-05-13** (Example Chief Risk Officer (delegate)): close 2 gap(s)
21. **2026-05-13** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IR-01.
22. **2026-05-14** (Example Chief Risk Officer (delegate)): poam (CA-5): produce poam.csv with current status, dates, and milestones
23. **2026-05-14** (Example Chief Risk Officer (delegate)): close 1 gap(s)
24. **2026-05-14** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-VULN-01.
25. **2026-05-15** (Example Chief Risk Officer (delegate)): recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO
26. **2026-05-15** (Example Chief Risk Officer (delegate)): close 1 gap(s)
27. **2026-05-16** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-REC-01.
28. **2026-05-16** (Example Chief Risk Officer (delegate)): identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report
29. **2026-05-16** (Example Chief Risk Officer (delegate)): close 1 gap(s)
30. **2026-05-17** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-IAM-01.
31. **2026-05-17** (Example Chief Risk Officer (delegate)): crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy
32. **2026-05-18** (Example Chief Risk Officer (delegate)): close 1 gap(s)
33. **2026-05-18** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-LOG-01.
34. **2026-05-18** (Example Chief Risk Officer (delegate)): network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix
35. **2026-05-19** (Example Chief Risk Officer (delegate)): close 1 gap(s)
36. **2026-05-19** (Example Chief Risk Officer (delegate)): linked KSIs: KSI-INV-01.
37. **2026-05-21** (Example Chief Risk Officer (delegate)): Re-run assessment validation and attach closure evidence for assessor re-test.
