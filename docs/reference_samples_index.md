# Reference samples index

This document explains **why each file under `reference_samples/`** exists, **what part of Observable Security Agent** it informs, and **whether direct code reuse** is appropriate.

> **Rule:** `reference_samples/` is **not imported by runtime code**. Use it for design, adapters, fixtures, and documentation only.

See also `reference_samples/README.md` and `reference_samples/manifest.json` (source of truth for paths and licenses).

---

## Prowler (`reference_samples/prowler/`)

| File | Why it is a strong representative | Informs our… | Reuse |
| --- | --- | --- | --- |
| `compliance/aws_well_architected_framework_reliability_pillar_aws.json` | Small real compliance mapping JSON (control/requirement structure). | Compliance CSV/JSON adapters; mapping keys for `control_mapper` / POA&M control strings. | Study only |
| `checks/aws_iam_user_accesskey_unused.metadata.json` | Canonical **check metadata** card (Provider, CheckID, Severity, ResourceType, etc.). | Scanner finding / eval metadata vocabulary; alignment with RA-5 style exports. | Study only |
| `outputs/generic_compliance_fixture.json` | Test fixture for generic compliance writer. | Report bundle shape ideas; correlation between findings and framework rows. | Study only |
| `schemas/output_metadata_fixture.json` | Sidecar metadata for outputs. | `eval_results.json` / run manifest fields (versioning, timestamps). | Study only |
| `docs/*_excerpt.md(x)` | Official docs on reporting formats & compliance exports. | CLI UX, assessor narrative, OCSF/CSV/JSON export expectations. | Study only |

**Adapter / schema / test / report:** primarily **adapter + schema** research; optional **fixture** synthesis; **report layout** cues from compliance/tutorial docs.

---

## Cartography (`reference_samples/cartography/`)

| File | Why representative | Informs our… | Reuse |
| --- | --- | --- | --- |
| `graph_models/cartography_metadata_schema.md` | Short module metadata schema doc. | Future **graph adapter** (nodes/edges) and documentation of asset relationships. | Study only |
| `schemas/detector_expectations_example.json` | Declarative detector expectations. | **Evidence gap matrix** / quality gates; test-style assertions on graph invariants. | Study only |
| `docs/README_excerpt.md` | Product positioning for asset inventory graphs. | Differentiating **inventory graph** vs **evidence correlation** in README/docs. | Study only |
| `docs/AGENTS_excerpt.md` | Contributor conventions excerpt. | If we add Cartography-aligned contributions or codegen. | Study only |

**Adapter / schema / test / report:** **future graph adapter** + **test** patterns; not current runtime.

---

## ElectricEye (`reference_samples/electriceye/`)

| File | Why representative | Informs our… | Reuse |
| --- | --- | --- | --- |
| `checks/electriceye_secgroup_auditor_config.json` | JSON driving public exposure / SG logic. | **Fixture** design for `network.public_admin_port_opened`; RA-5 exposure heuristics. | Study only |
| `checks/Amazon_EC2_Security_Group_Auditor_excerpt.py.txt` | Truncated auditor showing boto3 call patterns & checks. | AWS **collection** script safety & scope (not eval core); never copy into `evals/`. | **false** |
| `checks/ElectricEye_AttackSurface_Auditor_excerpt.py.txt` | Cross-service attack-surface checks (truncated). | Correlation ideas across services; **not** canonical model logic. | **false** |
| `outputs/ElectricEye_AWS_Policy.json` | Least-privilege IAM policy for scanner. | `scripts/collect_aws_evidence.py` permission hardening reference. | Study only |
| `docs/README_excerpt.md` | Architecture overview. | Positioning vs multi-cloud auditors. | Study only |

**Adapter / schema / test / report:** **fixtures** + **AWS collection** hardening; evals stay provider-neutral.

---

## AuditKit Community Edition (`reference_samples/auditkit/`)

| File | Why representative | Informs our… | Reuse |
| --- | --- | --- | --- |
| `evidence_packages/examples_README.md` | Describes example/evidence output layout. | Future **evidence package zip** layout; `validate_outputs.py` artifact completeness lists. | Study only |
| `schemas/nist_800_53_framework_doc_excerpt.md` | NIST 800-53 framework documentation (truncated). | `control_mapper`, `auditor_questions.md`, FedRAMP-oriented wording. | Study only |
| `reports/cli_reference_stub.html` | Tiny static HTML page. | Optional HTML report skin / CI artifact preview. | Study only |
| `docs/*_excerpt.md` | README, SECURITY, getting started (truncated). | Permissions model, CLI patterns, security communications. | Study only |

**Adapter / schema / test / report:** **report layout** + **evidence package** design; framework text for **docs/tests** tone.

---

## OCSF schema (`reference_samples/ocsf/`)

| File | Why representative | Informs our… | Reuse |
| --- | --- | --- | --- |
| `schemas/finding.json` | Compact **Finding** object schema. | Mapping scanner outputs / Prowler OCSF JSON to our `ScannerFinding` / semantic events. | Study only |
| `schemas/cloud.json` | Cloud context object. | Cloud account/project/region normalization in `Asset` / events. | Study only |
| `schemas/version.json` | Schema version pin. | Version negotiation if we add OCSF import/export. | Study only |
| `examples/base_event.json` | Base event schema. | Telemetry normalization and **semantic_type** crosswalk. | Study only |
| `docs/*_excerpt.md` | README + extensions (truncated). | Extension / `unmapped` fields (per Prowler OCSF discussions). | Study only |

**Adapter / schema / test / report:** **schema** + future **OCSF adapter**; may drive **fixtures** for round-trip tests.

---

## Licenses (`reference_samples/licenses/`)

Upstream `LICENSE` files are copied **verbatim** for attribution. They do not ship application logic.

---

## Summary: direct code reuse?

| Project | Default |
| --- | --- |
| JSON schemas / fixtures / compliance maps | **Study** → inform our own schemas & tests; do not paste large chunks without review. |
| Python excerpts (`.py.txt`) | **false** — illustrative only; **do not** drop into `evals/` or `core/`. |
| HTML / MD docs | **false** for code reuse; **true** for paraphrasing and citing in our docs with attribution. |

When in doubt, set `direct_code_reuse_allowed` to **false** and open a dedicated integration task.
