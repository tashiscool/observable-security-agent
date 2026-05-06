# Observable Security Agent Demo

Observable Security Agent is an agentic compliance operations platform. This demo shows how it turns fixture cloud telemetry, scanner data, configuration evidence, control requirements, deterministic validation, recommendations, guardrails, and human review into machine-readable and human-readable assurance evidence.

The demo is FedRAMP-oriented and OSCAL-inspired. It supports ATO package work, but it does not claim the fixture system is FedRAMP-certified or approved.

## What The Demo Shows

- AWS ECR/container vulnerability findings from fixture scanner data.
- Cloud configuration evidence for baseline/configuration monitoring.
- Identity/access evidence for IAM role and MFA posture.
- Audit logging evidence for CloudTrail delivery to central logging.
- Stale scan evidence that is preserved but not used as primary RAG support.
- Missing evidence for a control that remains `INSUFFICIENT_EVIDENCE`.
- One unresolved high vulnerability mapped to `RA-5` and `SI-2`.
- One scanner finding reviewed by a human as `FALSE_POSITIVE`.
- One scanner finding reviewed by a human as `RISK_ACCEPTED`.
- Machine-readable and human-readable assurance package outputs.

## Commands

Run the full offline golden path:

```bash
python agent.py golden-path-demo --output-dir build/assurance-package-demo
```

Run the focused test:

```bash
python -m pytest tests/test_golden_path.py -q
```

Run the full suite:

```bash
python -m pytest -q
```

No network access, real cloud credentials, or external LLM calls are required.

## Expected Outputs

The golden path writes these files under `build/assurance-package-demo/`:

- `assurance-package.json`
- `executive-summary.md`
- `control-assessment-report.md`
- `open-risks.md`
- `evidence-table.md`
- `reviewer-decisions.md`
- `metrics.json`
- `eval_results.json`
- `eval_summary.md`
- `agent-run-log.json`

## Architecture Talk Track

The story is a pipeline:

1. Collectors load raw fixture scanner and cloud configuration records.
2. Normalizers convert those records into stable `EvidenceArtifact` and `NormalizedFinding` schemas.
3. Control requirements load as explicit machine-readable objects.
4. Deterministic validators check evidence presence, freshness, and unresolved high/critical vulnerabilities.
5. The control mapping engine maps evidence and findings to controls without relying on an LLM.
6. RAG context bundles select fresh, scoped evidence and explicitly exclude stale or out-of-scope sources.
7. Recommendation generation creates structured, review-gated actions.
8. Guardrails block unsupported claims, certification language, destructive actions, stale primary support, and malformed outputs.
9. Human review decisions are recorded as preserved evidence, not automatic approvals.
10. Package generators write OSCAL-inspired JSON and assessor-friendly Markdown.
11. Metrics and evals show the workflow is observable and testable.

## What Makes It Agentic

The platform does more than scan and report. It plans and executes an assurance workflow over bounded evidence:

- It retrieves only scoped context for each control.
- It explains why evidence is selected or excluded.
- It generates recommendations from validation results.
- It records agent run logs for each workflow stage.
- It routes compliance-impacting conclusions through human review.
- It produces packages that can be inspected by machines and people.

## Safety Guardrails

The demo includes deterministic guardrails:

- Missing evidence is never treated as passing evidence.
- Stale evidence is preserved but not used as primary support unless explicitly allowed.
- Every factual recommendation must cite `evidenceIds` or explicit missing evidence.
- Compliance-impacting recommendations require human review.
- The agent does not approve controls, close POA&Ms, suppress findings, delete evidence, or certify compliance.
- Certification language such as """certified,""" """ATO-ready approved,""" or unsupported """compliant""" claims is blocked without human review support.
- Structured package output is schema validated before writing.

## Where Evidence IDs Appear

Evidence IDs appear in:

- `assurance-package.json` under `evidence`, `findings`, `controlMappings`, `validationResults`, `agentRecommendations`, and `assessmentResults`.
- `control-assessment-report.md` beside each control, finding, validation result, and recommendation.
- `open-risks.md` for each open critical/high finding.
- `evidence-table.md` as the evidence inventory.
- `reviewer-decisions.md` to show which evidence supported each human decision.

## Human Review Preservation

Human decisions are preserved in `humanReviewDecisions` and in `reviewer-decisions.md`. The demo records:

- `FALSE_POSITIVE` for a reviewed scanner finding.
- `RISK_ACCEPTED` for a reviewed vendor dependency risk.
- `NEEDS_MORE_EVIDENCE` where the control lacks sufficient support.

These decisions do not automatically certify a control or close remediation. They are audit evidence for the assurance package.

## How This Differs From A Scanner Or Report Generator

A scanner emits findings. A report generator formats text.

Observable Security Agent builds an assurance evidence chain:

- Raw source record -> normalized evidence -> mapped control -> deterministic validation -> scoped RAG context -> recommendation -> guardrail result -> human review -> package artifact -> metrics/evals.

That chain is why the demo can show not just """what was found,""" but whether the evidence is fresh, mapped, reviewable, explainable, and package-ready for human-reviewed ATO support.
