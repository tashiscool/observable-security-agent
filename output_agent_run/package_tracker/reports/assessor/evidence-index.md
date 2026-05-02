# Evidence index

This index lists traceable artifacts referenced in the package snapshot. Checksums are included only when present in `reconciliation_summary`.

| Artifact | Path / URI | Checksum or digest |
| --- | --- | --- |
| Machine-readable package (body hash) | `fedramp20x-package.json` | `f1800b0da41fb377955bc9b1cdd2ccc35cd9612166b3df037429b89535060ae7` |
| Assessment output directory | `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/output_agent_run` | Not computed here. |
| Evidence graph / link target | `evidence_graph.json` | Not recorded per link in package. |

## Human-readable reports (manifest)

- `reports/assessor/assessor-summary.md` — role `assessor`
- `reports/executive/executive-summary.md` — role `executive`
- `reports/agency-ao/ao-risk-brief.md` — role `agency_ao`
- `reports/reconciliation_report.md` — role `reconciliation`

## Limitations

- Per-file SHA-256 for every on-disk artifact is not part of the nested package JSON; use the package body digest when provided, or external integrity controls.
- This index does not assert completeness of the assessment output directory.
