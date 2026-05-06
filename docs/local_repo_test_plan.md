# Local Repo Test Plan — `observable-security-agent`

> Snapshot taken from a read-only inspection of the repo at
> `<repo>`
> on 2026-05-02. Behavior was not modified during inspection.

This document is the canonical "what's in the box and how to verify it locally" guide.
It covers commands, fixtures, tests, package/build, web/API, missing/broken paths,
implemented vs. stubbed features, and the exact sequence to verify everything end-to-end.

---

## 1. Existing commands

### 1a. `agent.py` (the CLI)

`python3 agent.py <subcommand> ...` — single entry point. Subcommands wired in `agent.py:573-923`:

| Subcommand              | Purpose                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `assess`                | Load evidence (fixture or AWS raw bundle), run all evals, write reports to `--output-dir`.           |
| `threat-hunt`           | Agentic-AI threat hunt; writes `threat_hunt_findings.json` + queries + POA&M hints.                  |
| `run-agent`             | **Bounded autonomous loop** (observe → plan → act → verify → explain); writes `agent_run_trace.json`/`agent_run_summary.md` + downstream 20x package. |
| `secure-agent-arch`     | Render reference secure-agent architecture markdown.                                                 |
| `report`                | Re-render reports from a previously written `eval_results.json`.                                     |
| `list-evals`            | Print eval IDs and NIST 800-53 control mappings.                                                     |
| `validate`              | Validate generated artifacts under `--output-dir` (post-assess gate).                                |
| `validate-20x-package`  | JSON Schema validation of `fedramp20x-package.json`.                                                 |
| `generate-20x-reports`  | Re-render the executive / assessor / AO / machine-readable / reconciliation markdown reports.        |
| `reconcile-20x`         | REC-001…REC-010 deep reconciliation of package vs. reports.                                          |
| `reconcile-reports`     | Lighter cross-report consistency check.                                                              |
| `build-20x-package`     | Build a complete `fedramp20x-package.json` + companion files from an `--assessment-output` dir.      |
| `import-findings`       | Normalize external scanner output (Prowler, OCSF) and merge into the assessment.                    |

### 1b. `Makefile` targets

`Makefile:28-114`:

| Target                    | What it runs                                                                                          |
| ------------------------- | ----------------------------------------------------------------------------------------------------- |
| `install`                 | `pip install -r requirements.txt`.                                                                    |
| `test`                    | `python3 -m pytest`.                                                                                  |
| `verify-demo`             | `bash scripts/verify_demo.sh` (pytest + `make all` + BuildLab harness + AWS path).                   |
| `verify-all-features`     | `bash scripts/verify_all_features.sh` (every CLI subcommand, every script, API, web, optional live AWS via `OS_AGENT_CSV`). |
| `aws-bootstrap-verify`    | CSV → /tmp session creds → STS → `verify-demo`. Requires `CSV_FILE=/path/to/accessKeys.csv`.          |
| `demo`                    | `python3 scripts/demo_script.py --write-only` → `output/demo_walkthrough.md`.                         |
| `assess-fixture`          | `python3 agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir $(OUTPUT_DIR)`. |
| `assess-fixture-agentic`  | Same, scenario `scenario_agentic_risk`, output `$(OUTPUT_AGENTIC)`.                                   |
| `collect-aws`             | `python3 scripts/collect_aws_evidence.py --region $(REGION) --output-dir $(RAW_EVIDENCE_DIR)`.        |
| `assess-aws`              | `python3 agent.py assess --provider aws --raw-evidence-dir $(RAW_EVIDENCE_DIR) --output-dir $(OUTPUT_DIR)`. |
| `build-20x`               | `python3 agent.py build-20x-package --assessment-output $(OUTPUT_DIR) --config $(CONFIG_DIR) --package-output $(dir $(PACKAGE_JSON))`. |
| `validate-20x`            | `python3 agent.py validate-20x-package --package $(PACKAGE_JSON) --schemas $(SCHEMAS_DIR)`.           |
| `reports`                 | `python3 agent.py generate-20x-reports --package $(PACKAGE_JSON) --config $(CONFIG_DIR)`.             |
| `reconcile`               | `python3 agent.py reconcile-20x --package $(PACKAGE_JSON) --reports $(REPORTS_ROOT)`.                 |
| `web`                     | `python3 scripts/serve_web.py` (static Evidence Explorer at http://127.0.0.1:8080/web/index.html).    |
| `validate-output`         | `python3 scripts/validate_outputs.py --output-dir $(OUTPUT_DIR)`.                                     |
| `validate-output-agentic` | Same, against `$(OUTPUT_AGENTIC)`.                                                                    |
| `validate-agentic-loop`   | `python3 agent.py run-agent --provider fixture --scenario scenario_agentic_risk --output-dir $(OUTPUT_AGENTIC) --package-output $(OUTPUT_AGENTIC)/agent_run_20x`. |
| `all`                     | `assess-fixture validate-output build-20x validate-20x reports reconcile validate-agentic-loop demo`. |

Variables are documented at the top of the `Makefile` and may be overridden on the command line:
`REGION`, `RAW_EVIDENCE_DIR`, `PROFILE`, `OUTPUT_DIR`, `OUTPUT_AGENTIC`, `CONFIG_DIR`,
`SCHEMAS_DIR`, `PACKAGE_JSON`, `REPORTS_ROOT`.

### 1c. Helper scripts (`scripts/`)

| Script                          | Purpose                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------------------- |
| `buildlab_readiness.py`         | BuildLab readiness harness: env, fixture demos, 20x package, static web, submission gate.|
| `collect_aws_evidence.py`       | Collect raw AWS API evidence as JSON (and optionally fixture-shaped companion files).    |
| `demo_script.py`                | Print/write `output/demo_walkthrough.md` for the live demo.                              |
| `export_aws_session_env.py`     | Emit bash `export AWS_*=...` lines from a session-creds JSON.                            |
| `export_graph_cypher.py`        | Convert `output/evidence_graph.json` to Cypher MERGE statements.                         |
| `run_aws_assessment.py`         | Convenience wrapper for assess against an AWS evidence export directory.                 |
| `run_fixture_assessment.py`     | Convenience wrapper for the bundled demo fixture scenario.                               |
| `serve_web.py`                  | Static HTTP server so `/web/index.html` and `/output/*` load in a browser.               |
| `validate_outputs.py`           | Hard-fail gate that the build produced the complete evidence package.                    |
| `aws_bootstrap_verify.sh`       | CSV → `/tmp` session creds → packer validate → `verify-demo`.                            |
| `verify_all_features.sh`        | Exhaustive feature verification — every CLI subcommand, every script, API, web, optional live AWS. |
| `verify_demo.sh`                | pytest + `make all` + BuildLab + AWS path checks.                                        |

### 1d. Optional `api/` (FastAPI)

`api/server.py` — `app = FastAPI(...)`. Endpoints:

- `GET  /api/health` → `{"status": "ok"}`
- `POST /api/explain` → grounded explain (uses LLM if `AI_API_KEY` is set, otherwise deterministic fallback that cites the evidence contract). See `api/explain.py:568` for `call_openai_compatible(...)` and `api/explain.py:594` for `run_explain(...)`.

Run the API locally with `python3 -m uvicorn api.server:app --port 8081` (requires `pip install '.[api]'`).

---

## 2. Existing fixture scenarios

Three fixture scenarios live under `fixtures/` (plus a small `agent_security/` payload):

| Scenario                                | Demonstrates                                                                                       |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `scenario_public_admin_vuln_event`      | Cloud-style FAILs: public admin port + critical vuln + matching log/event but missing alert/ticket. Used by `make assess-fixture` and `make all`. |
| `scenario_20x_readiness`                | "Green path" — all controls satisfied, intended for FedRAMP 20x readiness validation.              |
| `scenario_agentic_risk`                 | Agentic-AI telemetry (`agent_identities.json`, `agent_tool_calls.json`, `agent_memory_events.json`, `agent_policy_violations.json`) plus cloud evidence to trigger every `AGENT_*` eval and the agentic threat hunt. |

`fixtures/agent_security/agent_assessment_pass.json` is a bundled "all green" agent telemetry payload used by `secure-agent-arch` and `agent_security_outputs`.

---

## 3. Existing test count

`pytest --collect-only` reports **332 tests collected** across 52 test files in `tests/`. Notable groupings:

- `test_agent_cli.py` — argparse smoke tests for every `agent.py` subcommand.
- `test_agent_evals.py`, `test_agent_loop.py`, `test_secure_agent_architecture.py`, `test_threat_hunt_agentic.py` — agentic AI surface.
- `test_fedramp20x_*`, `test_schema_validator_20x.py` — package builder + schema gate.
- `test_assessor_report_bundle.py`, `test_executive_report_bundle.py`, `test_agency_ao_report_bundle.py`, `test_report_outputs.py`, `test_report_writer_bundle.py` — report generation.
- `test_fixture_*`, `test_aws_provider.py`, `test_aws_evidence_raw.py` — provider matrix.
- `test_validate_outputs.py`, `test_deep_reconciliation.py` — gating.
- `test_api_explain.py` — deterministic explain modes.
- `test_web_sample_data_contract.py` — web UI sample-data schema.
- `test_import_findings.py`, `test_reference_backed_samples.py`, `test_reference_samples.py` — external-tool ingestion.

---

## 4. Existing package/build commands

End-to-end FedRAMP 20x package build, in dependency order:

```bash
python3 agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir output
python3 scripts/validate_outputs.py --output-dir output
python3 agent.py build-20x-package --assessment-output output --config config --package-output evidence/package
python3 agent.py validate-20x-package --package evidence/package/fedramp20x-package.json --schemas schemas
python3 agent.py generate-20x-reports --package evidence/package/fedramp20x-package.json --config config
python3 agent.py reconcile-20x --package evidence/package/fedramp20x-package.json --reports evidence/package
```

Equivalent shorthand:

```bash
make assess-fixture validate-output build-20x validate-20x reports reconcile
```

External findings ingestion uses `python3 agent.py import-findings --source <prowler|ocsf> --input <file> --output-dir output`.

Package outputs land in:

- `evidence/package/fedramp20x-package.json` — single machine-readable SoR (schema-validated).
- `evidence/package/reports/{executive,assessor,agency-ao,machine-readable}/*.md` — audience-targeted reports.
- `evidence/package/reports/reconciliation_report.md` — package vs. reports alignment.

---

## 5. Existing web / API commands

- **Static Evidence Explorer**:

  ```bash
  make web
  # → open http://127.0.0.1:8080/web/index.html
  ```

  The page loads sample data from `web/sample-data/*` by default, or your `output/` artifacts when present (`agent_run_trace.json`, `agent_run_summary.md`, `eval_results.json`, `evidence_graph.json`, `correlations.json`, `instrumentation_plan.md`, `auditor_questions.md`, `evidence_gap_matrix.csv`, `secure_agent_architecture.md`, `20x-package/fedramp20x-package.json`).

- **FastAPI explain service** (optional):

  ```bash
  pip install '.[api]'         # adds fastapi, uvicorn[standard], httpx
  python3 -m uvicorn api.server:app --port 8081
  curl -s http://127.0.0.1:8081/api/health
  curl -s -X POST http://127.0.0.1:8081/api/explain \
       -H 'content-type: application/json' \
       -d '{"mode":"explain_eval","audience":"assessor","selected_eval":{"eval_id":"…"}}'
  ```

  Without `AI_API_KEY` the response is a deterministic, evidence-cited string that ends with the `Evidence contract` footer. With `AI_API_KEY` set, it uses an OpenAI-compatible chat-completions call (`AI_API_BASE`, `AI_MODEL` overridable; `httpx` only).

---

## 6. Missing commands or broken paths

Inspection of `Makefile`, `agent.py`, and `scripts/` did not surface any missing or dead-end commands; everything documented in `make help` is wired and exercised by `scripts/verify_all_features.sh`.

Items that *intentionally* exit non-zero in some configurations and are not bugs:

- `scenario_20x_readiness` is the green/live-style path. Validate it with `--mode live` (`python3 scripts/validate_outputs.py --output-dir <dir> --mode live` or `python3 agent.py validate --output-dir <dir> --mode live`) because that scenario intentionally may have no FAIL evals and no `POAM-AUTO-*` rows.
- `python3 -m uvicorn api.server:app` requires the optional `[api]` extra (`fastapi`, `uvicorn`, `httpx`). Without it, `from api.server import app` fails with `ModuleNotFoundError: fastapi`. The CLI core (`assess`, `threat-hunt`, `run-agent`, `build-20x-package`, …) does not depend on the API extra.
- `make collect-aws` / `make assess-aws` / `make aws-bootstrap-verify` / live-AWS sections of `verify_all_features.sh` require valid AWS credentials and are skipped automatically when `OS_AGENT_CSV` is not set.

No broken paths or missing files were found. `evidence/package/` and `evidence/package_agentic/` exist as committed sample bundles and are also regenerated by `make build-20x` / `make all`.

---

## 7. Implemented vs. stubbed features

### Fully implemented and exercised by tests

- All 14 evals: `CM8_INVENTORY_RECONCILIATION`, `RA5_SCANNER_SCOPE_COVERAGE`, `AU6_CENTRALIZED_LOG_COVERAGE`, `SI4_ALERT_INSTRUMENTATION`, `CROSS_DOMAIN_EVENT_CORRELATION`, `CM3_CHANGE_EVIDENCE_LINKAGE`, `CA5_POAM_STATUS`, `RA5_EXPLOITATION_REVIEW`, `AGENT_TOOL_GOVERNANCE`, `AGENT_PERMISSION_SCOPE`, `AGENT_MEMORY_CONTEXT_SAFETY`, `AGENT_APPROVAL_GATES`, `AGENT_POLICY_VIOLATIONS`, `AGENT_AUDITABILITY` (each with a registered `EVAL_ID` constant in `evals/*.py`).
- `core/` engine: `evaluator.py`, `normalizer.py`, `evidence_graph.py`, `report_writer.py`, `poam.py`, `failure_narrative_contract.py`, `evidence_contract.py`, `secure_agent_architecture.py`, `threat_hunt_agentic.py`, `agent_security_outputs.py`.
- `fedramp20x/` package builder + JSON Schema gate + report builder + reconciliation (REC-001…REC-010).
- `agent_loop/` bounded autonomy: `policy.py` (allow/deny lists), `planner.py` (`Observation` + `Plan`), `actions.py` (10 distinct act steps), `runner.py` (`run_bounded_agent_loop` writes trace + summary).
- `providers/`:
  - `fixture.FixtureProvider` — fully implemented for all three scenarios.
  - `aws.AWSProvider` and `aws.AwsEvidenceProvider` — fully implemented; `aws_evidence_raw.collect_aws_raw_evidence` mirrors fixture-compatible companion files into the region-specific raw dir.
  - `prowler`, `ocsf`, `electriceye`, `auditkit`, `azure_gcp_normalizers`, `exposure_policy` — implemented for `import-findings` and report enrichment.
- `instrumentation/` query generators — `aws_cloudtrail`, `gcp_logging`, `sentinel`, `splunk`, `agent_telemetry`, `context`.
- `normalization/ocsf_export.py` — OCSF event export.
- `api/explain.py` — deterministic and LLM-backed paths, both tested (LLM path via `httpx.MockTransport` in `scripts/verify_all_features.sh`).
- `web/` — static SPA (`index.html`, `app.js`, `fedramp20x.js`, `styles.css`) + sample-data fixtures.

### Intentional "no remediation" boundaries

- `agent_loop/policy.py:BLOCKED_UNTIL_APPROVAL` blocks `cloud_remediation`, `permission_change`, `destructive_change`, `external_notification`, `real_ticket_create`. The bounded loop logs each policy decision in `agent_run_trace.json` rather than executing these actions — by design.
- `actions.action_draft_tickets_json_only` only emits a JSON draft; it never POSTs to a ticketing system.

### No features are stubbed-out or marked TODO

A search for `TODO`, `FIXME`, `pass  # stub`, `NotImplementedError` in `core/`, `evals/`, `fedramp20x/`, `agent_loop/`, `api/`, and `providers/` shows no incomplete implementations affecting the CLI, package build, web, or API paths.

---

## 8. Exact command sequence to verify everything

### A. Quick gate (≈15 s)

```bash
cd <repo>
python3 -m pip install -r requirements.txt   # one-time
make test                                    # 332 tests
make all                                     # assess-fixture → validate-output → build-20x → validate-20x → reports → reconcile → validate-agentic-loop → demo
```

Expected: pytest reports `332 passed`. `make all` writes `output/`, `output_agentic/`, `evidence/package/*`, and `output/demo_walkthrough.md` with no non-zero exits.

### B. Fixture-only end-to-end (≈30 s)

```bash
make assess-fixture validate-output build-20x validate-20x reports reconcile
make assess-fixture-agentic validate-output-agentic validate-agentic-loop
python3 agent.py threat-hunt --provider fixture --scenario scenario_agentic_risk --output-dir output_agentic
python3 agent.py secure-agent-arch --output-dir output_agentic
python3 agent.py import-findings --source prowler --input tests/fixtures/prowler/prowler_sample_results.json --output-dir output
python3 agent.py import-findings --source ocsf    --input tests/fixtures/ocsf/sample_detection.json --output-dir output
```

### C. Web + API smoke

```bash
make web                                          # http://127.0.0.1:8080/web/index.html
pip install '.[api]'                              # one-time, optional
python3 -m uvicorn api.server:app --port 8081 &
curl -s http://127.0.0.1:8081/api/health
curl -s -X POST http://127.0.0.1:8081/api/explain \
     -H 'content-type: application/json' \
     -d '{"mode":"explain_eval","audience":"assessor"}'
```

### D. Comprehensive verification (≈70 s, fixture-only)

```bash
make verify-demo            # pytest + make all + BuildLab + AWS-shaped raw
make verify-all-features    # every subcommand, every script, API, web, mocked LLM, optional live AWS
```

### E. Live AWS round-trip (optional, requires CSV access keys)

```bash
OS_AGENT_CSV=/path/to/accessKeys.csv REGION=us-gov-west-1 make verify-all-features
# or:
make aws-bootstrap-verify CSV_FILE=/path/to/accessKeys.csv REGION=us-gov-west-1
```

### Pass criteria

- `make test` → `332 passed`.
- `make all` → exit 0; produces:
  - `output/eval_results.json`, `output/assessment_summary.json`, `output/poam.csv`, `output/evidence_graph.json`, `output/correlations.json`, `output/instrumentation_plan.md`, `output/auditor_questions.md`, `output/evidence_gap_matrix.csv`.
  - `evidence/package/fedramp20x-package.json` (schema-valid) and `evidence/package/reports/{executive,assessor,agency-ao,machine-readable,reconciliation_report.md}`.
  - `output_agentic/agent_run_trace.json`, `output_agentic/agent_run_summary.md`, `output_agentic/agent_run_20x/fedramp20x-package.json`.
  - `output/demo_walkthrough.md`.
- `make verify-all-features` → `PASS=32  SKIP=0  FAIL=0` (all subcommands and scripts) when run without `OS_AGENT_CSV`; with `OS_AGENT_CSV` set, the live-AWS section is also `PASS`.
