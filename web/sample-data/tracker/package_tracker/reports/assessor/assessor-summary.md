# Assessor summary

> **Not a FedRAMP approval.** This document is part of a **FedRAMP 20x–style** evidence snapshot for engineering and assessment workflow support. It does **not** constitute a FedRAMP-approved package, 3PAO attestation, or Authorizing Official decision. Machine-readable validation uses this repository’s **FedRAMP 20x–style evidence package schema** (`schemas/fedramp20x-package.schema.json`), not an official GSA JSON schema unless you explicitly import one elsewhere.


**Audience:** 3PAO, FedRAMP reviewer, technical assessor.

## System and scope (from package)

- **System id:** `SYS-OBS-EXAMPLE-001`
- **Short name:** example_security_observability_program
- **Impact level:** moderate
- **Authorization / deployment notes:** boundary id ``, model `customer_managed_cloud`

### Customer vs. inherited (from `authorization_scope`)

**In scope (customer-asserted categories):**

- `compute_workloads`
- `security_operations_evidence`

**Out of scope (with rationale):**

- `Physical data centers` — Inherited from cloud service provider; not customer-configurable.
- `Provider-managed network edge` — Outside customer administrative boundary; evidence limited to customer plane configuration.

## Generated assessor bundle

The following files were generated from the same `fedramp20x-package.json` snapshot:

- `assessor-summary.md`
- `ksi-by-ksi-assessment.md`
- `evidence-index.md`
- `validation-methodology.md`
- `exceptions-and-manual-evidence.md`
- `poam.md`

## Evidence index (assessor companion)

Use **`evidence-index.md`** in this directory for artifact paths, package digest pointers, and the human report manifest.

## Validation run metadata and input manifest

`fedramp20x-package.json` → `package_metadata` is authoritative for machine-readable fields below.

### Schema validation

- **Outcome:** `passed`
- **Validated at:** `2026-05-03T02:01:20.207241+00:00`
- **Tool version:** `0.1.0`
- **CLI:** `agent.py run-agent --workflow tracker-to-20x --input /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/assessment_tracker/sample_tracker.csv --output-dir /Users/tkhan/IdeaProjects/security-infra/observable-security-agent/validation_run/agent_run_tracker`
- **Package generation (UTC):** `2026-05-03T02:01:20.191221+00:00`

### Input artifacts (assessment directory)

| Path | SHA-256 (prefix) | Size (bytes) |
| --- | --- | ---: |
| `eval_results.json` | `11ecf5b15b7644d3…` | 41992 |
| `evidence_graph.json` | `b7907e2457fdc21b…` | 63938 |
| `assessment_summary.json` | `0197b61dd7628824…` | 223 |
| `poam.csv` | `dc26c1aa2faca41e…` | 901 |

### Evidence source coverage (summary)

- **Registered sources:** 32
- **automation_percentage:** 8.33
- **ksis_missing_required_evidence:** 0
- **ksi_manual_mode_count:** 1

### Provider / scope summary

- **Deployment model:** customer_managed_cloud
- **Impact level:** moderate

### Framework / control summary

- **Catalog KSIs:** 12
- **Unique Rev5 controls (crosswalk):** 71

### Package manifest (validation slices, relative paths)

- `evidence/validation-results/ksi-results.json`
- `evidence/validation-results/findings.json`
- `evidence/validation-results/poam-items.json`
- `evidence/validation-results/evidence-links.json`


## Count reconciliation (machine-readable fields)

| Measure | Package array length | `reconciliation_summary.counts` | Parsed from assessor/poam markdown |
| --- | ---: | --- | ---: |
| KSI results | 12 | `12` | 12 |
| Findings | 18 | `18` | 18 |
| POA&M items | 18 | `18` | 18 |

Counts match between arrays and reconciliation snapshot (or reconciliation counts omitted).

## Evidence maturity (package snapshot)

- **Evidence maturity automation %** (KSIs with automation score ≥ 4): **8.33%** (1 of 12 catalog KSIs).
- **Catalog `validation_mode` counts — manual / hybrid / automated:** 1 / 11 / 0.
- **KSIs with missing required evidence** (registry gap — not attestation): **0**.
- **KSIs on manual or file-primary path** (registered sources; low automation by design): **2**.


## Traceability chain (this snapshot)

Rev4/Rev5 controls → **20x KSI** (`ksi_catalog` / results) → **criteria** (`pass_fail_criteria`) → **evidence sources** (registry) → **eval results** → **findings** → **POA&M** → this report set.


## KSI status overview

| KSI | Status |
| --- | --- |
| `KSI-AGENT-01` | `PASS` |
| `KSI-AGENT-02` | `FAIL` |
| `KSI-AGENT-03` | `PASS` |
| `KSI-AGENT-04` | `PASS` |
| `KSI-CM-01` | `FAIL` |
| `KSI-IAM-01` | `FAIL` |
| `KSI-INV-01` | `FAIL` |
| `KSI-IR-01` | `FAIL` |
| `KSI-LOG-01` | `FAIL` |
| `KSI-REC-01` | `FAIL` |
| `KSI-SCRM-01` | `PASS` |
| `KSI-VULN-01` | `FAIL` |

## Findings overview

| Finding | Severity | Linked KSIs | POA&M (on row) |
| --- | --- | --- | --- |
| `FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417` | high | KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01 | `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001` |
| `FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6` | high | KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01 | `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001` |
| `FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8` | high | KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01 | `POAM-AUTO-SI4-ALERT-INSTRUMENTATION-001` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6` |
| `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` | critical | KSI-AGENT-02, KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-REC-01, KSI-VULN-01 | `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760` |

## Metadata

- **Generated at:** 2026-05-03T02:01:20.191218+00:00
- **Generator:** observable-security-agent/fedramp20x
- **Assessment output URI:** `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/validation_run/agent_run_tracker`
- **Reconciliation parity:** `aligned`
