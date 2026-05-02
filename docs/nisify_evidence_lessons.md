# Nisify evidence lessons (reference only)

[Nisify](https://github.com/clay-good/nisify) is used here as a **reference for evidence aggregation and transparency**, not as a mandate to adopt **NIST CSF 2.0** as our only framework. This product remains **FedRAMP 20x / NIST 800-53 Rev. 4–5–aligned** (KSI catalog, control crosswalk, evaluation pipeline). Local excerpts live under `reference_samples/nisify/`.

## Evidence collection model

**Nisify (reference):** Normalizes vendor artifacts into a common envelope (`platform`, `evidence_type`, `collected_at`, `raw_data`, `metadata`) — see `reference_samples/nisify/evidence_model/*.json`. Collection is positioned as **read-only API** pull from many SaaS/cloud systems plus exports.

**Our model:** `config/evidence-source-registry.yaml` defines canonical source **ids** used by KSI criteria (`evidence_required`), with `collection_method`, `frequency`, `evidence_format`, and optional `typical_channel` (documentation-only hint: `saas_api_readonly`, `manual_governance_attestation`, etc.). Assessments consume **file/hybrid/API-shaped** bundles through the same registry vocabulary.

## NIST CSF mapping (reference vs. this repo)

**Nisify:** Maps evidence types to **NIST CSF 2.0** subcategories with explicit `required_evidence_types`, `platforms`, `logic`, and `freshness_days` — see `reference_samples/nisify/mappings/control_evidence_mappings_excerpt.json` and `nist_mapping_doc_excerpt.md`.

**We do not** replicate CSF 2.0 as the sole spine. Controls roll through **Rev. 4 → Rev. 5 → 20x KSI** crosswalks and `config/ksi-catalog.yaml`. CSF-style ideas we **borrow**: separating **API-collectible** from **manual governance** evidence classes, and making mapping rules **auditable** (see deterministic scoring below).

## Deterministic scoring

**Nisify:** Markets “transparent, deterministic scoring” — no ML; scores trace to evidence and rules (`reference_samples/nisify/reports/README_product_excerpt.md`, mapping doc).

**Our parallel:** `fedramp20x/evidence_maturity.py` computes **per-source maturity 0–5** and **per-KSI automation scores** from registry fields and catalog `validation_mode`, with explicit caps (e.g. missing `evidence_required` ids in the registry). We added **`compute_ksi_evidence_posture`** to separate:

- **Missing required evidence** — criterion ids not in the registry (implementation gap).
- **Manual or file-primary path** — ids are registered; low automation is **expected** (attestation, PDF, narrative), not “missing.”

## Dashboard / report model

**Nisify:** Executive-facing maturity and dashboard narrative in product README (excerpt).

**Our parallel:** `fedramp20x/report_builder.py` — `security-posture-dashboard.md`, `assessor-summary.md`, and `exceptions-and-manual-evidence.md` surface **evidence maturity automation %**, **`validation_mode` counts** (manual / hybrid / automated), and the **missing vs. manual** split from `assessment_correlation_snapshot.evidence_maturity_summary`. Top-level packages built via `build_fedramp20x_package` mirror key fields under `summary` for portability.

## Manual governance document handling

**Nisify mapping excerpt** notes a large share of CSF subcategories as **manual evidence required**; policies and narratives are first-class.

**We treat:** `collection_method: manual`, `evidence_format: markdown|pdf|screenshot`, and catalog `validation_mode: manual` as **expected** paths. They are **not** labeled “missing” unless a criterion references an **unregistered** source id. Reports and `evidence_posture` on each `ksi_validation_result` make that distinction explicit.

## Cloud / SaaS evidence sources

**Nisify:** Enumerates many SaaS connectors and API-collectible subcategories.

**We align conceptually** by documenting `collector` strings (e.g. `splunk_rest_api|okta_api|providers.aws_evidence_raw`), `typical_channel` hints, and **limitations** per source. FedRAMP-relevant AWS collectors remain first-class in the lower section of the registry; the pattern is the same **typed registry + provenance**, not a single vendor’s connector list.

## What we explicitly do *not* do

- We do **not** switch the product to **NIST CSF 2.0–only** control numbering or replace KSIs with CSF subcategories.
- We do **not** import Nisify runtime code; samples are for **lesson extraction** and gap awareness (`docs/reference_gap_matrix.md`).

## Traceability

| Reference sample | Lesson applied here |
|----------------|---------------------|
| `nisify/evidence_model/*.json` | Registry + normalized bundle philosophy |
| `nisify/mappings/*.json` / `nist_mapping_doc_excerpt.md` | Explicit evidence-to-control logic, freshness metaphor → our criteria + registry |
| `nisify/reports/README_product_excerpt.md` | Deterministic scoring claim → `evidence_maturity` + dashboards |
| `nisify/docs/config.example.yaml` | Environment/config separation → our `config/*.yaml` |
