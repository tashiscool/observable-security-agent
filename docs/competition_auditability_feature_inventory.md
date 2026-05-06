# Competition Auditability Capability Inventory

This inventory is the competition-facing map of how the checked-in reference material fuels Observable Security Agent and how each capability can be audited. It is intentionally broader than a demo script: the BuildLab demo can show a narrow slice, while this document keeps the full assessment platform visible and testable.

## Reference Usage Posture

- `reference_samples/manifest.json` tracks **72** copied reference samples from **12** upstream projects. The samples include scanner outputs, schema excerpts, graph models, report/package examples, docs, and compliance mappings.
- The samples are design inputs, adapter examples, and vocabulary anchors. They are **not runtime dependencies** and are not copied into live outputs.
- `tests/test_reference_samples.py` enforces the manifest, verifies every copied sample is accounted for, and checks that runtime packages do not reference the `reference_samples` path.
- Existing traceability docs remain supporting material: `docs/reference_gap_matrix.md`, `docs/reference_to_implementation_traceability.md`, `docs/buildlab_reference_backed_demo.md`, and `docs/reference_samples_index.md`.

## Reference Material Coverage

| Reference project | Samples | What it fuels in Observable Security Agent |
| --- | ---: | --- |
| `prowler` | 11 | CSPM finding import, compliance mapping style, Prowler output contracts, exposure-to-control normalization. |
| `cloudsploit` | 6 | Scanner result parsing, public exposure patterns, CloudSploit CSV/JSON import behavior. |
| `electriceye` | 6 | AWS check vocabulary, failed-check examples, scanner evidence normalization. |
| `aurelian` | 4 | External reconnaissance and public exposure reasoning without becoming a recon engine. |
| `cloudgraph-cli` | 4 | Asset graph concepts, cloud asset relationship vocabulary, graph export shape. |
| `fixinventory` | 5 | Inventory snapshot/reconciliation ideas, discovered asset modeling, boundary comparison. |
| `cartography` | 5 | Relationship graph semantics, detector expectation examples, asset/finding linkage. |
| `ocsf-schema` | 7 | Event/finding normalization vocabulary and OCSF adapter contracts. |
| `nisify` | 7 | NIST-shaped maturity scoring, evidence aggregation posture, report organization. |
| `FedRAMP20xMCP` | 5 | FedRAMP 20x KSI pattern lookup ideas and requirement/pattern schema influence. |
| `knox-fedramp-20x-pilot` | 5 | 20x package examples, machine-readable assessment/package expectations. |
| `auditkit` | 7 | Audit package/report layout ideas, read-only assessment posture, multi-framework narrative structure. |

Reference categories represented in the manifest: `checks`, `collector_output`, `compliance`, `compliance_mapping`, `config`, `docs`, `evidence_packages`, `evidence_reporting`, `evidence_sample`, `examples`, `fedramp_package_example`, `graph_model`, `graph_models`, `license`, `outputs`, `recon_pattern`, `reports`, `requirement_lookup`, `scanner_check`, `scanner_output`, `schema`, `schema_fixture`, and `schemas`.

## Complete Auditability Feature List

| # | Capability | Reference fuel | Implementation / config anchors | Auditability proof | Tests and gates |
| ---: | --- | --- | --- | --- | --- |
| 1 | Live and fixture AWS evidence ingestion | AuditKit read-only posture, scanner examples | `providers/aws.py`, `providers/aws_raw.py`, `agent.py assess` | Raw evidence manifests, canonical companion files, assessment bundle summary | `tests/test_aws_provider.py`, `tests/test_aws_evidence_raw.py`, `tests/test_agent_cli.py` |
| 2 | Multi-region AWS collection and permission coverage | AWS scanner projects, ElectricEye, Prowler | `providers/aws_raw.py`, `scripts/live_aws_verify_from_csv.py` | Per-region manifests, denied/skipped/success call records, confidence gaps | `tests/test_aws_evidence_raw.py`, `tests/test_guard_live_artifacts.py` |
| 3 | CSV and assessment tracker import | Legacy 3PAO tracker lessons, AuditKit package ideas | `core/csv_utils.py`, `classification/`, `agent.py import-assessment-tracker` | Parsed tracker items, row diagnostics, normalized evidence gaps | `tests/test_csv_utils.py`, `tests/test_assessment_tracker_import.py` |
| 4 | 3PAO spirit tracker corpus | Generic annual assessment workflow patterns | `fixtures/assessment_tracker/3pao_spirit_batch_*.csv`, `fixtures/assessment_tracker/3pao_spirit_manifest.yaml` | Synthetic tracker rows mapped to expected gap types and KSI counts | `tests/test_3pao_spirit_batches.py` |
| 5 | Evidence gap taxonomy and classification | 3PAO comments, FedRAMP/NIST control wording | `core/models.py`, `classification/classify_tracker_gap.py`, `core/evidence_gap.py` | Gap type, description, controls, mapped KSIs | `tests/test_evidence_gap.py`, `tests/test_tracker_evidence_gap_eval.py` |
| 6 | 3PAO reasonable-test artifact sufficiency | Assessor comment patterns, AuditKit evidence posture | `config/3pao-sufficiency-rules.yaml`, `ai/fallbacks.py`, `ai/prompts.py` | Artifact sufficiency findings that reject ticket shells and tracker text as proof | `tests/test_ai_reasoning.py` |
| 7 | AI reasoning with deterministic fallback and LLM backends | FedRAMP20xMCP pattern lookup, 3PAO reasoning examples | `ai/`, `scripts/evaluate_3pao_remediation.py`, Ollama/LiteLLM/Bedrock-compatible clients | Reasoned recommendation, residual gaps, remediation narrative, confidence explanation | `tests/test_ai_reasoning.py`, CLI smoke tests |
| 8 | ConMon reasonableness catalog | FedRAMP ConMon checklist and NIST cadence language | `config/conmon-catalog.yaml`, ConMon evaluators | Cadence-aware annual/monthly/weekly/daily evidence expectations | `tests/test_conmon_reasonableness.py` |
| 9 | Inventory reconciliation | CloudGraph, FixInventory, Cartography | `evals/inventory_coverage.py`, `core/evidence_graph.py` | Declared vs discovered vs scanner scope deltas | `tests/test_inventory_coverage.py`, `tests/test_deep_reconciliation.py` |
| 10 | Scanner scope coverage | Prowler, CloudSploit, ElectricEye | `evals/scanner_scope.py`, scanner import adapters | Assets missing from scan scope, stale scans, confidence notes | `tests/test_scanner_scope.py` |
| 11 | Vulnerability scanner imports | Prowler, CloudSploit, OCSF, ElectricEye | `adapters/prowler.py`, `adapters/cloudsploit.py`, `adapters/ocsf.py` | Normalized findings with severity, asset, control/KSI linkage | `tests/test_prowler_adapter.py`, `tests/test_cloudsploit_adapter.py`, `tests/test_ocsf_adapter.py`, `tests/test_import_findings.py` |
| 12 | Credentialed/privileged scan proof | 3PAO RA-5(5) evidence requests | Gap classifier and scanner-scope evidence checks | Findings distinguish scan result from privileged scan configuration proof | `tests/test_3pao_spirit_batches.py`, `tests/test_scanner_scope.py` |
| 13 | Exploitation review for high/critical vulnerabilities | 3PAO RA-5(8) tracker comments | `evals/vulnerability_exploitation_review.py`, `config/3pao-sufficiency-rules.yaml` | Proof that historic logs were reviewed for IoCs, not only that patches deployed | `tests/test_vulnerability_exploitation_review.py`, `tests/test_ai_reasoning.py` |
| 14 | Centralized log coverage | OCSF event vocabulary, 3PAO AU-6 evidence pattern | `evals/central_log_coverage.py` | Components with local logs, central log sources, missing forwarding gaps | `tests/test_central_log_coverage.py` |
| 15 | Local-to-central log correlation | OCSF and graph references | `evals/event_correlation.py`, `core/evidence_graph.py` | Same event traceable across local and centralized sources | `tests/test_event_correlation.py`, `tests/test_evidence_graph.py` |
| 16 | Alert rule instrumentation | 3PAO SI-4/AU-5 examples | `evals/alert_instrumentation.py`, `instrumentation/` | Alert rule definitions, recipients, sample notifications, response evidence | `tests/test_alert_instrumentation.py`, `tests/test_instrumentation_generators.py` |
| 17 | Incident and response ticket linkage | 3PAO IR-4/IR-6 tracker workflow | `evals/change_ticket_linkage.py`, evidence gap pipeline | Incident or alert evidence tied to investigation, notifications, closure | `tests/test_change_ticket_linkage.py`, `tests/test_tracker_evidence_gap_eval.py` |
| 18 | Change management chain | Generic 3PAO SIA/test/approval/deployment questions | `classification/`, `config/3pao-sufficiency-rules.yaml`, remediation evaluator | Security impact analysis, testing, approval, implementation, post-deploy verification chain | `tests/test_3pao_spirit_batches.py`, `tests/test_ai_reasoning.py` |
| 19 | POA&M and deviation handling | FedRAMP CA-5/RA-5 patterns, Knox examples | `poam/`, `config/poam-policy.yaml`, gap taxonomy including `deviation_request_missing` | POA&M rows, deviation request gaps, vendor dependency evidence needs | `tests/test_poam_core.py`, `tests/test_poam_builder.py`, `tests/test_poam_generation.py`, `tests/test_3pao_spirit_batches.py` |
| 20 | Backup and restore evidence | 3PAO CP-9/CP-10 evidence pattern | Gap classifier and sufficiency rules | Backup configuration separated from restore/integrity test evidence | `tests/test_3pao_spirit_batches.py`, `tests/test_ai_reasoning.py` |
| 21 | Identity, password, and privilege evidence | 3PAO AC/IA/CM-5 account evidence requests | Gap taxonomy, AWS IAM raw collection, tracker classification | Account listings, password policy, MFA, role/privilege review, recertification gaps | `tests/test_aws_evidence_raw.py`, `tests/test_3pao_spirit_batches.py` |
| 22 | Crypto, FIPS, KMS, and data protection evidence | Generic SC-13/SC-28 evidence requests | AWS raw collection, gap classification, control crosswalk | KMS/encryption settings, FIPS module proof requirements, unresolved crypto gaps | `tests/test_aws_evidence_raw.py`, `tests/test_3pao_spirit_batches.py` |
| 23 | Traffic-flow and boundary proof | 3PAO SC-7/CA-3/CM-7 comments | `config/system-boundary.yaml`, `config/authorization-scope.yaml`, classifier | Security groups, NACLs, routes, VPC endpoints, traffic policy exceptions | `tests/test_public_exposure_policy.py`, `tests/test_3pao_spirit_batches.py` |
| 24 | Public exposure policy | Aurelian, Prowler, CloudSploit, ElectricEye | `config/public-exposure-policy.yaml`, public exposure evaluators | Public admin, internet exposure, exception/remediation notes | `tests/test_public_exposure_policy.py`, `tests/test_public_admin_scenario_coverage.py` |
| 25 | FedRAMP 20x KSI package generation | FedRAMP20xMCP, Knox pilot | `fedramp20x/`, `config/ksi-catalog.yaml`, schemas | Machine-readable KSI package, evidence links, control crosswalk | `tests/test_fedramp20x_package.py`, `tests/test_fedramp20x_top_package.py`, `tests/test_schema_validator_20x.py`, `tests/test_tracker_to_20x.py` |
| 26 | Human/machine reconciliation | Knox pilot, AuditKit package ideas | `fedramp20x/reconciliation.py`, report bundles | Reconciliation output for machine package vs human-readable report | `tests/test_deep_reconciliation.py`, `tests/test_agency_ao_report_bundle.py` |
| 27 | Assessor, AO, executive, and web reports | AuditKit, Nisify, Knox pilot | `reports/`, `web/`, generated sample data contracts | Assessor report, executive summary, AO bundle, web explorer pages/screenshots | `tests/test_report_outputs.py`, `tests/test_assessor_report_bundle.py`, `tests/test_agency_ao_report_bundle.py`, `tests/test_executive_report_bundle.py`, `tests/test_web_sample_data_contract.py` |
| 28 | Evidence graph and Cypher export | CloudGraph, FixInventory, Cartography | `core/evidence_graph.py`, graph fixtures | Nodes/edges linking assets, events, findings, controls, gaps, tickets | `tests/test_evidence_graph.py`, `tests/fixtures/cartography/account_asset_finding_eval_poam.graph.json` |
| 29 | Bounded autonomous workflow | AuditKit read-only posture, BuildLab challenge needs | `agent_loop/`, `core/agent_models.py`, policy fixtures | Agent run trace, allowed/disallowed action records, no destructive cloud operations | `tests/test_agent_loop.py`, `tests/test_agent_workflow.py`, `tests/test_secure_agent_architecture.py` |
| 30 | Threat-hunt and agentic-risk workflows | OCSF, SIEM-style event semantics | `evals/threat_hunt_agentic.py`, `scenarios/` | Threat-hunt findings connected to assets, events, and response needs | `tests/test_threat_hunt_agentic.py`, `tests/test_scenario_agentic_risk.py` |
| 31 | Secret and live artifact guards | AuditKit read-only posture, competition safety needs | `scripts/`, guard tests, validation policy | No source credential commit, no live ARNs/accounts/raw evidence in sample data | `tests/test_guard_live_artifacts.py`, `tests/test_scan_generated_outputs.py` |
| 32 | BuildLab demo/readiness harness | BuildLab runbook and competition screenshots | `docs/buildlab_agentlab_runbook.md`, `docs/competition/`, package scripts | Feature screenshots, deterministic fixture demo artifacts, readiness checks | `tests/test_buildlab_readiness.py`, `tests/test_package_demo_artifacts.py`, `docs/competition/*.png` |

## What This Means For Judging

The reference material does not merely sit in the repo. It feeds four competition-critical layers:

1. **Input compatibility:** Scanner and event references become adapters and normalization contracts.
2. **Assessment reasoning:** 3PAO tracker examples and FedRAMP/NIST cadence language become explicit gap types, sufficiency rules, and AI prompts.
3. **Audit packaging:** Knox, AuditKit, FedRAMP20xMCP, and Nisify patterns shape 20x packages, reports, maturity scoring, and reconciliation.
4. **Proof discipline:** Tests prove reference samples are accounted for, runtime code stays independent, and each advertised auditability capability has a file/config/test anchor.

The core differentiator is not that Observable Security Agent replaces Prowler, CloudSploit, Splunk, Wazuh, Jira, ServiceNow, or Smartsheet. It uses those ecosystems as evidence sources, then performs the 3PAO-style reasonableness test: whether the artifacts actually prove the stated control behavior across assets, logs, alerts, tickets, POA&M, and FedRAMP 20x KSI outputs.
