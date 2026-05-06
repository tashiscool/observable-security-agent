# Security posture dashboard

> **Not a FedRAMP approval.** This document is part of a **FedRAMP 20x–style** evidence snapshot for engineering and assessment workflow support. It does **not** constitute a FedRAMP-approved package, 3PAO attestation, or Authorizing Official decision. Machine-readable validation uses this repository’s **FedRAMP 20x–style evidence package schema** (`schemas/fedramp20x-package.schema.json`), not an official GSA JSON schema unless you explicitly import one elsewhere.


**Audience:** CEO, CTO, COO, CFO, program leadership, capture/proposal leadership.

## KPIs (this package snapshot)

| Metric | Value |
| --- | ---: |
| Total KSIs (catalog size used for automation %) | 12 |
| KSI status: PASS | 4 |
| KSI status: FAIL | 8 |
| KSI status: PARTIAL / OPEN rolled here | 0 |
| KSI status: NOT_APPLICABLE / other | 0 |
| Catalog automation-target KSIs | 10 |
| **Automation percentage** (share of catalog KSIs flagged `automation_target`) | **83.33%** |
| Automation-target KSIs with PASS this run | 3 / 10 |
| Open / active POA&M rows | 18 |
| Open critical findings | 15 |
| Open high findings | 3 |
| Total findings in package | 18 |
| **Evidence maturity automation %** (catalog KSIs with maturity score ≥ 4) | **8.33%** |
| Catalog KSIs — manual `validation_mode` | 1 |
| Catalog KSIs — hybrid `validation_mode` | 11 |
| KSIs — manual/file-primary evidence path (registered sources; expected attestation) | 2 |

## Machine vs. human package reconciliation

- **Parity status (package):** `aligned`
- **Meaning:** `aligned` means the reconciliation record matched counts in this snapshot; `review_required` means the package explicitly flags a gap (for example missing human report paths).

## Automation target (plain language)

- **83.33%** of catalog KSIs are designated for automation-heavy validation (`automation_target` true). That percentage describes catalog design, not pass rate.
- Of those **10** automation-target KSIs, **3** show **PASS** in this run.

**Automation-target KSIs not at PASS:**
- KSI-IAM-01 (FAIL)
- KSI-LOG-01 (FAIL)
- KSI-VULN-01 (FAIL)
- KSI-CM-01 (FAIL)
- KSI-INV-01 (FAIL)
- KSI-IR-01 (FAIL)
- KSI-AGENT-02 (FAIL)

## Blockers vs. manageable residual (evidence-only)

**Blockers (authorization / sale-relevant):**

- **KSI FAIL count (8)** — failing KSIs are material gaps until remediated or formally excepted with assessor agreement.
- **Open critical findings (15)** — executive escalation and funding for remediation typically required.

**Manageable residual (still requires leadership attention but not necessarily a hard stop):**

- **Open high findings (3)** — schedule remediation and monitor until closed.
- **Open POA&M items (18)** — track owners and dates; residual risk remains until closure.

## Leadership actions (from POA&M rows only)

Owners and dates below are copied from machine-readable POA&M fields. Rows with no owner or date are shown as *not stated in package*.

| POA&M / focus | Owner (package) | Target date | Expected impact (package) |
| --- | --- | --- | --- |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-05 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Generate SPL/KQL/GCP/AWS query. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Add enabled alert. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: Add recipient list. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Produce sample alert evidence. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Link alert to incident/change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-06-05 | Planned remediation step (package). |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-05 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Generate SPL/KQL/GCP/AWS query. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Add enabled alert. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: Add recipient list. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Produce sample alert evidence. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Link alert to incident/change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-06-05 | Planned remediation step (package). |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-05 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Generate SPL/KQL/GCP/AWS query. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Add enabled alert. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: Add recipient list. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Produce sample alert evidence. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Link alert to incident/change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-06-05 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-B89FA44F2251` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-21 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: inventory (CM-8, CM-8(1), CM-8(3), CA-7): produce declared_inventory.csv reconciled against discovered_assets.json | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: scanner_vulnerability (RA-5, RA-5(3), RA-5(5), SI-2, RA-5(8)): produce scanner_targets.csv with credentialed=true + plugin/profile evidence | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json export from latest credentialed scan | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: logging (AU-2, AU-3, AU-6, AU-12): produce central_log_sources.json plus a local audit log sample correlated with the central index | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: alerting (AU-6, SI-4, SI-4(1), SI-4(4), IR-4, IR-6): produce sample_alert_ref pointing at an executed alert export | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: close 3 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01, KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: change_management (CM-3, SI-2): produce tickets.json field security_impact_analysis=true with SIA attachment | Example Chief Risk Officer (delegate) | 2026-05-11 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: linked KSIs: KSI-CM-01. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: incident_response (SI-4(1), SI-4(4), IR-4, IR-6): produce tickets.json entry citing the alert with documented response | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: close 2 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IR-01. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: poam (CA-5): produce poam.csv with current status, dates, and milestones | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: linked KSIs: KSI-VULN-01. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| Step: recovery (CP-9, CP-10): produce restore_tests.json with measured RTO/RPO | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| Step: linked KSIs: KSI-REC-01. | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: identity_access (AC-2, AC-2(7), AC-6): produce identity_users.json + privileged-account flag + MFA report | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-16 | Planned remediation step (package). |
| Step: linked KSIs: KSI-IAM-01. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: crypto (SC-13, SC-28, SC-12): produce FIPS 140-2/3 module list + KMS rotation export + cipher policy | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: linked KSIs: KSI-LOG-01. | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: network_boundary (SC-7, SC-7(11)): produce data-flow diagram + security_group inventory + ports/protocols matrix | Example Chief Risk Officer (delegate) | 2026-05-18 | Planned remediation step (package). |
| Step: close 1 gap(s) | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: linked KSIs: KSI-INV-01. | Example Chief Risk Officer (delegate) | 2026-05-19 | Planned remediation step (package). |
| Step: Re-run assessment validation and attach closure evidence for assessor re-test. | Example Chief Risk Officer (delegate) | 2026-05-21 | Planned remediation step (package). |
