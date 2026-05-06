# Reconciliation report

**Parity status:** `aligned`

## Counts

```json
{
  "findings_machine": 18,
  "poam_items_machine": 18,
  "ksi_results": 12,
  "findings_human_reports": 18,
  "ksi_results_human_reports": 12,
  "poam_items_human_reports": 18,
  "human_report_parse_errors": [],
  "human_report_parse_applied": true
}
```

## Human report manifest

- `reports/assessor/assessor-summary.md` — assessor_summary
- `reports/assessor/ksi-by-ksi-assessment.md` — assessor_ksi_by_ksi
- `reports/assessor/evidence-index.md` — assessor_evidence_index
- `reports/assessor/validation-methodology.md` — assessor_methodology
- `reports/assessor/exceptions-and-manual-evidence.md` — assessor_exceptions
- `reports/assessor/poam.md` — assessor_poam_md
- `reports/assessor/assessor-summary.md` — assessor_primary
- `reports/executive/executive-summary.md` — executive
- `reports/agency-ao/ao-risk-brief.md` — agency_ao
- `reports/reconciliation_report.md` — reconciliation

## Package digest

`02c58c6ed5d2ffa29fd5e2cacf2902bd03c064f76e1555e782e41bbe1287fccc`

- Machine counts above are from package arrays. Human-row counts (parsed from rendered markdown) are applied after assessor/poam markdown exists — see `human_report_parse_applied`.