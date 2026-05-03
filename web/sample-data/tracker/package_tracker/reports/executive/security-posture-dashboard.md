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
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-7712019CD417` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-02 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Implement or enable SIEM detection for the assessed semantic with accountable recipients. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Add on-call / governance distribution lists to the rule. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Generate sample alert payload or saved-search proof with timestamps. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Link alert to incident or change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Re-run SI-4 alert instrumentation evaluation. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-02 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Implement or enable SIEM detection for the assessed semantic with accountable recipients. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Add on-call / governance distribution lists to the rule. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Generate sample alert payload or saved-search proof with timestamps. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Link alert to incident or change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Re-run SI-4 alert instrumentation evaluation. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-25E596D712C8` — SI-4 Alert Instrumentation Coverage | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-06-02 | Elevated exposure window with plausible exploitation or audit failure absent timely remediation. |
| Step: Implement or enable SIEM detection for the assessed semantic with accountable recipients. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Add on-call / governance distribution lists to the rule. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Generate sample alert payload or saved-search proof with timestamps. | Example Chief Risk Officer (delegate) | 2026-05-17 | Planned remediation step (package). |
| Step: Link alert to incident or change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-23 | Planned remediation step (package). |
| Step: Re-run SI-4 alert instrumentation evaluation. | Example Chief Risk Officer (delegate) | 2026-05-29 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Investigate affected asset(s); confirm boundary placement and authoritative owner. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Update declared inventory / IIW; resolve duplicate or stale rows. | Example Chief Risk Officer (delegate) | 2026-05-05 | Planned remediation step (package). |
| Step: Assign accountable owner for each in-scope asset row. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: Confirm scanner and central logging requirements for updated inventory classes. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Export refreshed inventory evidence and attach to POA&M milestone. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Investigate affected asset(s); confirm boundary placement and authoritative owner. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Update declared inventory / IIW; resolve duplicate or stale rows. | Example Chief Risk Officer (delegate) | 2026-05-05 | Planned remediation step (package). |
| Step: Assign accountable owner for each in-scope asset row. | Example Chief Risk Officer (delegate) | 2026-05-08 | Planned remediation step (package). |
| Step: Confirm scanner and central logging requirements for updated inventory classes. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Export refreshed inventory evidence and attach to POA&M milestone. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Run generated exploitation-review queries; retain analyst identity and time range. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Export SIEM/log results and attach to vulnerability ticket. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Document analyst or agent conclusion for in-exploitability decision. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Link ticket to scanner finding IDs (`linked_finding_ids`). | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: Re-run RA-5(8) evaluation with evidence pointers. | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Configure central log forwarding for affected assets and required event types. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Produce paired local + central log excerpts for the same event IDs. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Validate last_seen / receipt timestamps meet policy window. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Document retention, integrity, and RBAC for the central store. | Example Chief Risk Officer (delegate) | 2026-05-13 | Planned remediation step (package). |
| Step: Re-run AU-6 style coverage evaluation and attach results. | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Implement or enable SIEM detection for the assessed semantic with accountable recipients. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Add on-call / governance distribution lists to the rule. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Generate sample alert payload or saved-search proof with timestamps. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Link alert to incident or change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Re-run SI-4 alert instrumentation evaluation. | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Implement or enable SIEM detection for the assessed semantic with accountable recipients. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Add on-call / governance distribution lists to the rule. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Generate sample alert payload or saved-search proof with timestamps. | Example Chief Risk Officer (delegate) | 2026-05-10 | Planned remediation step (package). |
| Step: Link alert to incident or change response workflow. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Re-run SI-4 alert instrumentation evaluation. | Example Chief Risk Officer (delegate) | 2026-05-15 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Create or link formal change / incident ticket for the assessed event. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Complete security impact analysis (SIA) and testing evidence per CM-3. | Example Chief Risk Officer (delegate) | 2026-05-06 | Planned remediation step (package). |
| Step: Obtain documented approval aligned to change class. | Example Chief Risk Officer (delegate) | 2026-05-09 | Planned remediation step (package). |
| Step: Attach deployment evidence (automation receipt or timestamped record). | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Attach verification evidence (post-change scan or health check). | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` — Tracker Evidence Gap Analysis | Example Chief Risk Officer (delegate); Example System Owner (ISSO delegate) | 2026-05-18 | Potential for severe service disruption, data exposure, or regulatory breach until remediated. |
| Step: Document root cause and in-scope impact for the finding. | Example Chief Risk Officer (delegate) | 2026-05-03 | Planned remediation step (package). |
| Step: Implement corrective actions per control family guidance. | Example Chief Risk Officer (delegate) | 2026-05-07 | Planned remediation step (package). |
| Step: Collect objective evidence of remediation. | Example Chief Risk Officer (delegate) | 2026-05-12 | Planned remediation step (package). |
| Step: Schedule independent validation for POA&M closure. | Example Chief Risk Officer (delegate) | 2026-05-14 | Planned remediation step (package). |
