# OCSF alignment (event / finding vocabulary reference)

We use the [Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io) **informally** as a **vocabulary and shape reference** for importing scanner-style detections and for exporting our canonical models to a JSON shape that toolchains expecting “OCSF-like” rows can consume.

## Scope

| Direction | What we do |
| --- | --- |
| **Import** | Parse **OCSF-like Detection Finding** JSON (see `providers/ocsf.py`) into `ScannerFinding`, optionally deriving companion `SecurityEvent` rows for correlation fixtures. |
| **Export** | Emit **OCSF-like** JSON from `SecurityEvent` and `ScannerFinding` (`normalization/ocsf_export.py`), not validated against a pinned OCSF JSON Schema in CI. |

## Labels (important)

- Outputs from `normalization/ocsf_export.py` and the **`export-ocsf`** CLI are labeled **`OCSF-like`** in the document envelope.
- We **do not** claim **OCSF compliance** or strict schema validation unless we add an explicit validator and pin a schema version later.
- Interop fields such as `class_uid` / `category_uid` are **indicative** (e.g. Detection Finding class `2004` as used in samples), not a certification of conformity.

## Canonical preservation

- **`semantic_type`**: Our closed vocabulary on `SecurityEvent` is always copied into `metadata.extensions.observable_security_agent.semantic_type` on export. On import from OCSF-like findings, we **also** store the mapped semantic type on **`ScannerFinding.metadata["semantic_type"]`** (see `providers/ocsf.map_ocsf_to_semantic_type`).
- **Raw provider metadata**: Import stashes non-modeled top-level keys in `metadata.import_extras` and structured OCSF blocks under `metadata.ocsf_*`. Export places the full agent-side metadata bag under `metadata.extensions.observable_security_agent.provider_agent_metadata` (for findings) or `provider_raw_metadata` (for events) so nothing is silently dropped.

## Code map

| Artifact | Role |
| --- | --- |
| `providers/ocsf.py` | `iter_ocsf_detection_records`, `ocsf_detection_to_scanner_finding`, `import_ocsf`, `import_ocsf_to_file` |
| `normalization/ocsf_export.py` | `security_event_to_ocsf_like_export`, `scanner_finding_to_ocsf_like_export`, `build_ocsf_like_bundle`, `export_ocsf_like_json` |
| `python agent.py import-findings --format ocsf --input <file> --output <scenario_dir>` | Writes `scanner_findings.json` under the scenario directory. |
| `python agent.py export-ocsf --assessment-output <dir> --output <relative-or-absolute-path>` | Writes a single JSON bundle (default path relative to assessment output when not absolute). |

## Reference samples

In-repo samples under `reference_samples/ocsf/` and fixture `tests/fixtures/ocsf/sample_detection.json` exercise the adapter; they are **not** authoritative OCSF corpus data.
