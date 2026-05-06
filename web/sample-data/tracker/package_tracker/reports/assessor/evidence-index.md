# Evidence index

This index lists traceable artifacts referenced in the package snapshot. Checksums are included only when present in `reconciliation_summary`.

| Artifact | Path / URI | Checksum or digest |
| --- | --- | --- |
| Machine-readable package (body hash) | `fedramp20x-package.json` | `02c58c6ed5d2ffa29fd5e2cacf2902bd03c064f76e1555e782e41bbe1287fccc` |
| Assessment output directory | `<tmp>/validation_run/agent_run_tracker` | Not computed here. |
| Evidence graph / link target | `evidence_graph.json` | Not recorded per link in package. |

## Human-readable reports (manifest)

- `reports/assessor/assessor-summary.md` — role `assessor_summary`
- `reports/assessor/ksi-by-ksi-assessment.md` — role `assessor_ksi_by_ksi`
- `reports/assessor/evidence-index.md` — role `assessor_evidence_index`
- `reports/assessor/validation-methodology.md` — role `assessor_methodology`
- `reports/assessor/exceptions-and-manual-evidence.md` — role `assessor_exceptions`
- `reports/assessor/poam.md` — role `assessor_poam_md`
- `reports/assessor/assessor-summary.md` — role `assessor_primary`
- `reports/executive/executive-summary.md` — role `executive`
- `reports/agency-ao/ao-risk-brief.md` — role `agency_ao`
- `reports/reconciliation_report.md` — role `reconciliation`

## Limitations

- Per-file SHA-256 for every on-disk artifact is not part of the nested package JSON; use the package body digest when provided, or external integrity controls.
- This index does not assert completeness of the assessment output directory.
