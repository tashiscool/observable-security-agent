# AGENTS.md

Guidance for future Codex tasks in this repository.

## Product Mission

Observable Security Agent is an agentic compliance operations platform that converts cloud telemetry, vulnerability data, configuration evidence, and control requirements into explainable machine-readable and human-readable assurance packages.

It is not just a scanner, crosswalk, or report generator. The product must preserve evidence provenance, run deterministic checks, assemble bounded context, generate grounded narratives, and leave human reviewers in control of compliance decisions.

## Engineering Principles

- Facts are deterministic.
- Context is retrieved.
- Narratives are generated.
- Decisions are human-reviewed.
- Evidence is preserved.
- Everything is logged.
- Missing evidence must never be treated as passing evidence.
- The agent may recommend, draft, validate, explain, assemble evidence, and route work.
- The agent may not approve controls, suppress findings, close POA&Ms, delete evidence, change cloud resources, or certify compliance without human approval.

Use AI/LLM behavior only as a reasoning and drafting layer over supplied evidence. Do not let generated text become the source of truth for compliance status.

## Architecture Boundaries

- Collectors collect raw evidence.
- Normalizers convert raw evidence into stable internal schemas.
- Validators perform deterministic checks.
- RAG/context builders assemble bounded evidence bundles.
- LLM/agent layers only reason over supplied evidence.
- Package generators create machine-readable and human-readable artifacts.
- Review workflows store human decisions.

Keep these boundaries explicit in code. A collector should not decide compliance. A report generator should not invent evidence. An LLM reasoner should not mutate source artifacts or mark work complete.

## Coding Rules

- Prefer small cohesive modules.
- Validate all external data at boundaries.
- Preserve timestamps, source system, source IDs, account IDs, region, resource IDs, scanner names, finding IDs, control IDs, and evidence IDs.
- No unsupported compliance claims.
- No silent failures.
- Every generated conclusion must include evidence references.
- Use deterministic logic for status classification when possible.
- Do not introduce network calls in tests.
- Add tests for every new module.
- Preserve fixture/demo behavior unless a task explicitly changes it.
- Keep live evidence, credentials, account identifiers, raw cloud exports, and generated secret-bearing artifacts out of committed sample data.
- If a generated output can include environment-specific values, redact or gate it before committing.
- Do not add dependencies unless the change genuinely requires them; prefer the current stack first.

## Required Status Vocabulary

Use this vocabulary for new compliance/evidence status fields unless an existing schema already defines a stricter compatible enum:

- `COMPLIANT`
- `NON_COMPLIANT`
- `PARTIALLY_COMPLIANT`
- `NOT_APPLICABLE`
- `INSUFFICIENT_EVIDENCE`
- `NEEDS_HUMAN_REVIEW`
- `COLLECTOR_FAILED`
- `SCAN_STALE`
- `EVIDENCE_UNAVAILABLE`
- `SOURCE_UNREACHABLE`
- `CONTROL_NOT_ASSESSED`

Map legacy statuses such as `PASS`, `FAIL`, `PARTIAL`, `OPEN`, or `GENERATED` at module boundaries rather than mixing vocabularies deep inside new platform models.

## Repository Shape

- `agent.py`: primary CLI entry point.
- `core/`: canonical models, evaluator orchestration, evidence graph, output validation, reports, POA&M helpers, evidence contracts.
- `providers/`: fixture, AWS, scanner, ticket, inventory, and telemetry import/normalization adapters.
- `evals/`: deterministic evaluation modules.
- `fedramp20x/`: FedRAMP 20x-style package builder, KSI mapping, evidence links, POA&M generation, report generation, reconciliation, schema validation.
- `ai/`: bounded AI reasoners, prompt builders, deterministic fallbacks, evidence-contract enforcement.
- `agent_loop/`: bounded local agent workflow and autonomy policy.
- `api/`: optional FastAPI explain/reasoner API.
- `normalization/`: assessment tracker and OCSF-style export helpers.
- `instrumentation/`: query and instrumentation templates.
- `scripts/`: validation, AWS collection, demo, readiness, packaging, and safety utilities.
- `web/`: static Security Evidence Explorer.
- `schemas/`: JSON Schemas.
- `config/` and `mappings/`: policy, KSI, evidence-source, control, and crosswalk configuration.
- `fixtures/` and `reference_samples/`: deterministic local test/demo inputs.
- `tests/`: pytest suite.

## Verification Commands

Run from the repository root:

```bash
cd /Users/tkhan/IdeaProjects/security-infra/observable-security-agent
```

Install:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install -e ".[dev]"
```

Optional API extras:

```bash
python3 -m pip install -e ".[api,dev]"
```

Full test suite:

```bash
python3 -m pytest
```

Focused validation after generating `output/`:

```bash
python3 agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir output
python3 scripts/validate_outputs.py --output-dir output
python3 agent.py validate --output-dir output
```

End-to-end local workflow:

```bash
make all
```

Comprehensive repository validation:

```bash
python3 scripts/validate_everything.py --tracker fixtures/assessment_tracker/sample_tracker.csv --output-root validation_run
```

BuildLab/readiness gate:

```bash
python3 scripts/buildlab_readiness.py --repo-root .
```

Generated-output and live-artifact safety checks:

```bash
python3 scripts/scan_generated_outputs.py
python3 scripts/guard_live_artifacts.py --paths output evidence web/sample-data docs fixtures
```

Static/syntax checks available without adding lint dependencies:

```bash
python3 -m compileall agent.py core providers evals fedramp20x ai api agent_loop normalization instrumentation scripts
node --check web/app.js
```

Makefile shortcuts:

```bash
make install
make test
make assess-fixture
make validate-output
make build-20x
make validate-20x
make reports
make reconcile
make verify-demo
make verify-all-features
make scan-outputs
make audit-reference-reuse
```

There is no dedicated lint tool configured in `pyproject.toml` at the time of writing. Treat `compileall`, `node --check`, schema validation, artifact guards, and pytest as the available verification gates unless a future change adds a formal linter.

## Test Discipline

- Do not call external APIs in tests.
- Prefer fixture-shaped evidence and temp directories.
- For live AWS or credentialed paths, keep tests opt-in and skipped unless explicit environment variables are set.
- Add unit tests for new models, parsers, validators, guardrails, package emitters, and report contracts.
- Add integration tests when a change crosses provider loading, evaluation, package generation, and validation.
- When changing generated human-readable reports, assert both the machine-readable source fields and the rendered text contract.

## Compliance Safety Rules

- Never state that a system is compliant unless deterministic evidence supports the exact scoped claim.
- Prefer `INSUFFICIENT_EVIDENCE` or `NEEDS_HUMAN_REVIEW` over optimistic assumptions.
- Distinguish technical failure from evidence gap, policy gap, instrumentation gap, unresolved risk, and risk acceptance.
- Risk acceptance must be explicit evidence from an authorized human workflow, not inferred from silence or stale POA&M status.
- Closing a POA&M, suppressing a finding, approving a control, or certifying compliance is always a human decision.
