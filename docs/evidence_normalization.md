# Evidence Normalization Developer Notes

The evidence normalization layer lives in `core/evidence_normalization.py`.

Its job is to convert scanner outputs, cloud configuration records, and telemetry rows into:

- `EvidenceArtifact`
- `NormalizedFinding`

These are platform-domain models from `core/domain_models.py`, not the legacy assessment pipeline models.

## Current Adapters

- `normalize_vulnerability_scan_json(path, scanner=...)`
- `normalize_cloud_config_json(path, source_system=...)`
- `normalize_container_scan_csv(path, scanner=...)`
- `normalize_existing_scanner_export(path, source_format=...)`

`normalize_existing_scanner_export` routes through the existing scanner adapters for Prowler, CloudSploit, ElectricEye, OCSF, and Nessus-like CSV, then emits the platform-domain objects.

## Adding A New Adapter

1. Load the source into `list[dict]` records.
2. Preserve source identifiers in each row when available:
   - `sourceSystem`
   - `sourceType`
   - `scanner`
   - `collectedAt`
   - `observedAt`
   - `accountId`
   - `region`
   - `resourceId`
   - `resourceArn`
   - `imageDigest`
   - `findingId`
   - `vulnerabilityId`
   - `packageName`
   - `packageVersion`
   - `rawRef`
3. Call `normalize_records(...)`.
4. Return `EvidenceNormalizationResult`.

Do not silently skip malformed rows. Add a `NormalizationDiagnostic` in `errors` with `row_index`, `raw_ref`, and a clear message.

## Normalization Rules

- Severity is normalized to:
  - `CRITICAL`
  - `HIGH`
  - `MEDIUM`
  - `LOW`
  - `INFORMATIONAL`
  - `UNKNOWN`
- Finding status is normalized to:
  - `OPEN`
  - `FIXED`
  - `SUPPRESSED`
  - `FALSE_POSITIVE`
  - `RISK_ACCEPTED`
  - `UNKNOWN`
- Finding deduplication uses:
  - `scanner + findingId` when `findingId` exists.
  - otherwise `scanner + vulnerabilityId + packageName + packageVersion + resourceId/imageDigest`.
- Container evidence should prefer `imageDigest` over image tags.
- If an image tag is present without a digest, emit a warning.
- Freshness is controlled by `FreshnessThresholds(current_days=..., stale_days=...)`.
- Never discard `rawRef`.

## Testing Expectations

Every new adapter should include tests for:

- valid source record
- malformed source record
- raw reference preservation
- account and region preservation
- severity/status normalization
- deduplication behavior when applicable
- stale evidence behavior when timestamps are present
