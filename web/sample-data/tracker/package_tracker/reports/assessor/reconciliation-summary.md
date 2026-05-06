# Reconciliation summary (deep checks)

**Reconciliation id:** `REC-7E3C8FE226BC`
**Generated:** 2026-05-06T03:08:16.523693+00:00
**Machine package:** `<tmp>/validation_run/agent_run_tracker/package_tracker/fedramp20x-package.json`
**Overall status:** **`pass`**

## Human inputs reviewed

- `reports/assessor/ksi-by-ksi-assessment.md` — assessor_ksi_by_ksi
- `reports/assessor/assessor-summary.md` — assessor_summary
- `reports/executive/executive-summary.md` — executive_summary
- `reports/executive/security-posture-dashboard.md` — executive_dashboard
- `reports/agency-ao/ao-risk-brief.md` — ao_brief

## Checks

| ID | Status | Description | Detail |
| --- | --- | --- | --- |
| REC-001 | pass | All KSIs in machine package appear in assessor report | All catalog KSIs present in ksi-by-ksi-assessment.md |
| REC-002 | pass | KSI status values match between machine package and assessor report | Statuses match for all package KSI rows with assessor sections. |
| REC-003 | pass | Executive summary counts match package summary | Executive summary headline counts match package metrics. |
| REC-004 | pass | AO report includes all open high/critical residual risks | All open high/critical finding ids appear in ao-risk-brief.md |
| REC-005 | pass | All open findings have POA&M references unless risk accepted | Open findings have poam_id or poam_items.finding_id |
| REC-006 | pass | All POA&M items reference valid findings | All poam finding_id values exist in findings[] |
| REC-007 | pass | All evidence source IDs in KSI catalog exist in evidence registry | All catalog evidence_sources registered |
| REC-008 | pass | All artifact paths listed in package exist under report root | Manifest and artifact paths resolve |
| REC-009 | pass | Automation percentage in executive reports equals computed catalog value | Matched expected 83.33% |
| REC-010 | pass | Every failed/partial KSI has assessor conclusion and cross-report mention | OK |
| REC-011 | pass | Reconciliation human-parsed markdown table counts match machine arrays (when parse applied) | reconciliation_summary human table counts match package array lengths. |
