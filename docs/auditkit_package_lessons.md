# AuditKit reference lessons (evidence package and report layout)

This note summarizes **AuditKit Community Edition** public examples and docs checked in under `reference_samples/auditkit/`. It compares their **assessor-oriented packaging narrative** to **our FedRAMP 20x–style evidence tree**—without implying we ship or validate AuditKit output.

## What the AuditKit samples describe

### Evidence package structure (examples README)

- **Interactive HTML** and **PDF** reports as primary auditor-facing deliverables (tabs, severity badges, console deep-links).
- **Terminal / scan logs** as raw evidence of what was executed.
- **Screenshots** for human verification workflows.
- Examples are framed as outputs of **`auditkit scan -provider … -framework …`** with optional **`-format pdf|html`** and **`-output`**.

### Report sections (inferred from excerpts)

- **Compliance score / dashboard** (visual posture).
- **Failed controls** with remediation hints (CLI-style “fix” commands in sample text).
- **Passed controls** with evidence pointers.
- **Manual documentation** call-outs (organizational controls not fully automatable).
- **Disclaimer** separating automated vs manual coverage (screenshot reference in samples index).

### Schema validation

- In-repo AuditKit samples are **marketing/structure excerpts**, not a vendored JSON Schema validator for their full report model.
- Our **structural** check is **`providers.auditkit.validate_auditkit_inspired_evidence_shape`**: it asserts concepts inspired by their README (findings, evidence links, POA&M, `package_metadata`) against **our** nested `fedramp20x-package` JSON—**not** upstream AuditKit runtime validation.

### Framework mapping

- **`nist_800_53_framework_doc_excerpt.md`** describes crosswalk thinking (SOC2/PCI/CMMC → NIST families) and “what AuditKit checks” per family—**policy narrative**, not our crosswalk file format.
- We map **Rev4 → Rev5 → 20x KSI** via `config/control-crosswalk.yaml` and `mappings/*.csv`, separate from AuditKit’s multi-framework product matrix.

### Remediation scripts

- Sample terminal output shows **suggested CLI remediation** (e.g. revoke security group ingress). We do **not** auto-generate cloud CLI remediations in package builders; POA&M and narrative reports carry **disposition and planner text** instead.

### Output folder organization

AuditKit examples emphasize:

- **`reports/`** — HTML/PDF and related assets.
- **Scan outputs / screenshots** — supporting artifacts alongside narratives.

Our layout (nested machine-readable + human bundles):

| AuditKit-inspired idea | Our path |
| --- | --- |
| Single place for “official” machine-readable snapshot | `evidence/package/fedramp20x-package.json` (or package root + mirror under `reports/machine-readable/`) |
| Slice exports for validators / explorers | `evidence/validation-results/*.json` |
| Assessor-facing markdown set | `reports/assessor/` |
| Executive / leadership set | `reports/executive/` |
| Agency / AO set | `reports/agency-ao/` |

### Evidence manifest / checksum pattern

- AuditKit HTML/PDF examples stress **clickable evidence** and console URLs; **Checksum / manifest** patterns in their public tree are not fully represented in our small excerpts.
- Our pipeline implements **SHA-256 inventories** via `evidence/package/checksums.sha256`, `evidence/validation-results/evidence-links.json`, and `package_metadata.package_integrity` (see `fedramp20x/evidence_links.py`).

## Comparison to our outputs (quick reference)

| Artifact | Role |
| --- | --- |
| `evidence/package/fedramp20x-package.json` | Nested **FedRAMP 20x–style** bundle: KSIs, findings, POA&M, reconciliation, **`package_manifest`**, **`validation_run`**, input artifact hashes. |
| `evidence/validation-results/ksi-results.json` | KSI validation rows mirror. |
| `evidence/validation-results/findings.json` | Findings slice. |
| `evidence/validation-results/poam-items.json` | POA&M slice. |
| `reports/assessor/` | Summary, KSI-by-KSI, **evidence index**, methodology, exceptions, POA&M markdown. |
| `reports/executive/` | Summary, posture dashboard, **authorization readiness**, major risks. |
| `reports/agency-ao/` | AO brief, decision support, **residual risk register**, **customer responsibility matrix**, inherited controls. |

## Additions aligned with AuditKit-style provenance

The nested package **`package_metadata`** now carries, where available:

- **Validation run metadata** — JSON Schema validation outcome and timestamp.
- **Input artifact manifest** — assessment inputs (e.g. `eval_results.json`) with **SHA-256** and size.
- **Tool version** — distribution version when discoverable.
- **CLI invocation** — best-effort `sys.argv` capture (may be truncated).
- **Package generation timestamp** — `generated_at` (existing) plus `validation_run.validated_at` after schema pass.
- **Evidence source coverage** — registry counts and evidence maturity summary.
- **Provider / deployment summary** — from `authorization_scope` / boundary context.
- **Framework / control summary** — KSI catalog and Rev5 crosswalk rollups.

`reports/machine-readable/package.manifest.json` mirrors key manifest fields for tools that expect a small sidecar next to the JSON package.

---

**Sources in-repo:** `reference_samples/auditkit/evidence_packages/examples_README.md`, `reference_samples/auditkit/docs/*.md`, `reference_samples/auditkit/schemas/nist_800_53_framework_doc_excerpt.md`, `reference_samples/auditkit/reports/cli_reference_stub.html`.
