# Reference project analysis

Short notes on OSS samples under `reference_samples/` (see `reference_samples/manifest.json`). Nothing here is vendored into runtime; we study shapes, vocabulary, and packaging ideas.

| Project | What we studied | Implication for this repo |
|--------|------------------|---------------------------|
| **Prowler** | Check metadata cards, compliance framework JSON, generic compliance fixture, output metadata template, reporting docs | Hardened `iter_prowler_records` to reject framework/metadata-only JSON; aligned `ScannerFinding.metadata` keys with check/compliance vocabulary. |
| **OCSF** | Finding object schema, cloud object, version pin, base event / extensions docs | Informed `providers/ocsf.py` field usage and `normalization/ocsf_export.py` extension slot for `semantic_type`. |
| **Cartography** | Graph metadata schema doc, detector expectations JSON, README | Informed `evidence_graph_dict_to_cypher` (topology export only; our node/edge model is original). |
| **ElectricEye** | Security-group auditor config (ports), auditor excerpts, IAM policy sample | Port/check patterns drove `config/public-exposure-policy.yaml` and `providers/electriceye.py` fixture adapter. |
| **AuditKit CE** | Evidence package README, framework doc excerpts, getting started | Informed `validate_auditkit_inspired_evidence_shape` and FedRAMP 20x bundle narrative in `fedramp20x/package_builder.py` (original implementation). |

Licenses under `reference_samples/licenses/` are legal reference only.
