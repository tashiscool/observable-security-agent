# FedRAMP 20x reference lessons (FedRAMP20xMCP and Knox pilot)

This document summarizes **reference samples** checked in under `reference_samples/` (FedRAMP20xMCP metadata and Knox FedRAMP 20x pilot examples). It informs how we structure **requirement lookup**, **KSI organization**, and **package shape** in this repo.

**Scope and limits**

- Outputs from this codebase are **FedRAMP 20x–style evidence packages** for engineering and assessment workflow support. They are **not** FedRAMP-approved packages, AO decisions, or official GSA/FedRAMP submissions unless you complete those processes separately.
- JSON Schemas under `schemas/` (for example `fedramp20x-package.schema.json`) are **custom, project-local** artifacts. We label them explicitly as a **FedRAMP 20x–style evidence package schema**; they are **not** copies of an official FedRAMP JSON schema unless documented as such file-for-file.

---

## FedRAMP20xMCP (reference)

**Location:** `reference_samples/fedramp20xmcp/`

### Requirement / pattern data shape

- **Server manifest** (`requirements/server.json`): MCP `server.schema.json` envelope (name, title, repository URL, PyPI package id). It describes *how* requirement data is served, not the full requirement corpus.
- **KSI / control patterns** (`mappings/ksi_patterns.yaml`): `pattern_id`, `family`, `nist_controls`, `tags`, `finding` templates, `evidence_artifacts` lists. This is a **policy-as-code / SAST-style** pattern catalog: human-oriented YAML with structured metadata and evidence hints.
- **Pattern schema excerpt** (`requirements/PATTERN_SCHEMA_V2_excerpt.md`): Documents a **versioned pattern schema** for validation (pattern types, severity, language hooks).

### Supported lookup / query model (inferred)

- Consumers typically resolve **pattern_id** or **tags** (for example `ksi`) and map to **NIST / FedRAMP control identifiers** (`nist_controls`, related FRR ids).
- The MCP model is **tool-oriented**: expose requirement/pattern content to agents and IDEs rather than shipping one frozen “assessment package” JSON.

### KSI / control family organization

- Patterns carry **`family: KSI`** and **`nist_controls`** (for example `fedramp-20x`) as affiliation metadata.
- **Control families** in the NIST sense (AC, AU, CM, …) appear indirectly via related controls on findings and evidence artifact definitions—not as a single nested “family → KSI” tree in the sampled YAML.

---

## Knox FedRAMP 20x pilot (reference)

**Location:** `reference_samples/knox_20x_pilot/`

### Package / validation results shape

- **`package_examples/ksi-validation-results.json`**: Top-level **`metadata`** (`schema_version`, `generated_at`, `evaluation_id`, product version), **`summary`** rollups (totals, pass/fail, score), and **`evidence`** array entries per KSI-style item (`Unique Evidence Number`, compliance status, literal evidence payloads, scores, remediation flags). Knox uses **human-oriented field names** (spaces, title case) in JSON.
- **`schemas/fedramp-output-schema.json`**: Knox’s **demonstration** schema for that shape (`fedramp-20x-v1` in sample metadata). Treat as **vendor/example** schema for comparison—not as our schema.

### Machine-readable vs narrative

- **`reports/machine-readable-assessment_overview.md`**: Short markdown overview pointing at JSON exports—shows a **split** between narrative/readme-style docs and **machine-readable** deliverables.
- **`docs/cloud-service-summary.md`**: Service-level narrative (boundaries, data flows, responsibilities).

### Evidence links

- Knox samples embed **literal evidence** (for example IAM user objects) **inside** validation JSON. Our design prefers **links + checksums** (`evidence_links`, `evidence/validation-results/evidence-links.json`, `checksums.sha256`) so large payloads stay addressable and integrity-checked without duplicating raw objects in the nested package.

### Report / reconciliation ideas drawn from pilots

- **Single summary object** (Knox `summary`) aligns with executive-style rollups; we mirror that with `_exec_metrics` + executive / AO bundles.
- **Per-item evidence arrays** suggest **traceability from KSI → criterion → collected proof**; we preserve chain as: **Rev4 evidence → Rev5 control → 20x KSI → validation criterion → evidence source → eval result → finding → POA&M → report**.

---

## How we apply this in `observable-security-agent`

| Area | Approach |
| --- | --- |
| Requirement lookup | Config + mappings (`ksi-catalog.yaml`, crosswalk CSVs, eval linkage in code) rather than MCP runtime in core builds. |
| Package JSON | **Nested** `fedramp20x-package.json` validated against **FedRAMP 20x–style** `fedramp20x-package.schema.json`; metadata includes **KSI catalog version** and **schema id URI / relative path**. |
| Integrity | Package metadata references **checksum manifest** and **evidence-links** bundle paths; nested `evidence_links` may include **per-artifact SHA-256** when resolvable. |
| Human views | **Assessor**, **executive**, and **agency / AO** report bundles share one snapshot; **reconciliation** compares machine JSON to parsed counts in rendered markdown. |

---

## Traceability chain (explicit)

1. **Rev4** control / evidence (via crosswalk and finding / eval provenance).
2. **Rev5** control id (normalized crosswalk rows).
3. **20x KSI** (`ksi_id` in catalog and validation results).
4. **Validation criterion** (`pass_fail_criteria` in catalog; criterion results on KSI rows where present).
5. **Evidence source** (`evidence_sources` + `evidence_source_registry`).
6. **Result** (eval / KSI status rollups).
7. **Finding** (`findings[]`).
8. **POA&M** (`poam_items[]` + linkage).
9. **Report** (assessor / executive / AO markdown + machine-readable mirror).

---

## Further reading (in-repo)

- `reference_samples/fedramp20xmcp/` — MCP server descriptor and pattern YAML samples.
- `reference_samples/knox_20x_pilot/` — Pilot package examples and readme-style reports.
- `docs/why_this_is_not_reinventing_the_wheel.md` — positioning vs. generic GRC and agent tooling.
