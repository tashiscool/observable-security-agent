# Observable Security Agent — common workflows
# Run from this directory (repository root containing agent.py, requirements.txt, Makefile).
#
# Documented variables (override on the command line: make assess-aws RAW_EVIDENCE_DIR=raw/aws):
#
#   REGION            AWS region for collect-aws (default: us-east-1). Also honored via AWS_REGION.
#   RAW_EVIDENCE_DIR  Output base directory for collect-aws (default: raw).
#   PROFILE           Optional AWS CLI / boto3 profile name for collect-aws (empty = default credentials).
#
#   OUTPUT_DIR        Assessment output directory for cloud-style assess + build-20x (default: output).
#   OUTPUT_AGENTIC    Directory for agentic fixture + bounded run-agent trace (default: output_agentic).
#   CONFIG_DIR        FedRAMP / agent config directory (default: config).
#   SCHEMAS_DIR       JSON Schema directory for validate-20x (default: schemas).
#   PACKAGE_JSON      Path to fedramp20x-package.json (default: evidence/package/fedramp20x-package.json).
#   REPORTS_ROOT      Directory containing reports/ for reconcile-20x (default: evidence/package).

PYTHON       ?= python3
REGION       ?= us-east-1
RAW_EVIDENCE_DIR ?= raw
PROFILE      ?=
OUTPUT_DIR   ?= output
OUTPUT_AGENTIC ?= output_agentic
CONFIG_DIR   ?= config
SCHEMAS_DIR  ?= schemas
PACKAGE_JSON ?= evidence/package/fedramp20x-package.json
REPORTS_ROOT ?= evidence/package

.PHONY: help install test demo verify-demo verify-all-features aws-bootstrap-verify assess-fixture assess-fixture-agentic collect-aws assess-aws validate-output validate-output-agentic validate-agentic-loop build-20x validate-20x reports reconcile web scan-outputs package-demo audit-reference-reuse all

help:
	@echo "Observable Security Agent — make targets"
	@echo ""
	@echo "  make install          pip install -r requirements.txt"
	@echo "  make test             pytest"
	@echo "  make verify-demo      bash scripts/verify_demo.sh (pytest + make all + BuildLab + bundle + AWS paths)"
	@echo "  make verify-all-features  bash scripts/verify_all_features.sh (every CLI subcommand, every script, API, web, optional live AWS via OS_AGENT_CSV)"
	@echo "  make aws-bootstrap-verify  CSV→/tmp session + STS + verify-demo (set CSV_FILE=/path/to/accessKeys.csv)"
	@echo "  make demo             write output/demo_walkthrough.md (BuildLab script; use demo_script.py without --write-only to print)"
	@echo "  make assess-fixture   cloud-style fixture → $(OUTPUT_DIR)/"
	@echo "  make assess-fixture-agentic  agentic-risk fixture → $(OUTPUT_AGENTIC)/"
	@echo "  make collect-aws      raw AWS evidence → $(RAW_EVIDENCE_DIR)/"
	@echo "  make assess-aws       assess using AWS raw bundle"
	@echo "  make build-20x        build fedramp20x package → evidence/package/"
	@echo "  make validate-20x     JSON Schema validate package"
	@echo "  make reports          regenerate markdown reports from package JSON"
	@echo "  make reconcile        REC-001…REC-010 deep reconciliation"
	@echo "  make web              serve Evidence Explorer (http://127.0.0.1:8080/web/index.html)"
	@echo "  make scan-outputs     scripts/scan_generated_outputs.py — secret/PII scan on output/, evidence/, web/sample-data/, ..."
	@echo "  make audit-reference-reuse  scripts/audit_reference_reuse.py — manifest/licenses/runtime import audit → validation_run/"
	@echo "  make package-demo     scripts/package_demo_artifacts.py — bundle demo artifacts -> demo_artifacts.zip + manifest"
	@echo "  make validate-output  scripts/validate_outputs.py on OUTPUT_DIR (post-assess gate)"
	@echo "  make validate-output-agentic  validate $(OUTPUT_AGENTIC)/ (after assess-fixture-agentic)"
	@echo "  make validate-agentic-loop bounded run-agent (agentic scenario → trace + 20x under $(OUTPUT_AGENTIC)/)"
	@echo "  make all              cloud fixture + 20x + bounded run-agent (agentic) + demo walkthrough (output/)"
	@echo ""
	@echo "Variables: REGION RAW_EVIDENCE_DIR PROFILE OUTPUT_DIR OUTPUT_AGENTIC CONFIG_DIR SCHEMAS_DIR PACKAGE_JSON REPORTS_ROOT"

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest

verify-demo:
	bash scripts/verify_demo.sh

# Exhaustive feature verification: every agent.py subcommand, every script, FastAPI server, static web, all scenarios.
# Optional live AWS path via OS_AGENT_CSV=/path/to/accessKeys.csv (REGION=us-gov-west-1 default).
# Optional: OS_AGENT_CSV=/path/to/accessKeys.csv REGION=us-gov-west-1 make verify-all-features
# (Only sets OS_AGENT_CSV/REGION in the child shell when passed as Make vars, so a pre-exported OS_AGENT_CSV still works.)
verify-all-features:
	bash -c '\
	  [ -n "$(OS_AGENT_CSV)" ] && export OS_AGENT_CSV="$(OS_AGENT_CSV)"; \
	  [ -n "$(REGION)" ] && export REGION="$(REGION)"; \
	  exec scripts/verify_all_features.sh'

aws-bootstrap-verify:
	@test -n "$(CSV_FILE)" || (echo "Set CSV_FILE=/path/to/accessKeys.csv (and optional REGION=...)" >&2; exit 2)
	bash scripts/aws_bootstrap_verify.sh --csv-file "$(CSV_FILE)" $(if $(strip $(REGION)),--region $(REGION),)

demo:
	$(PYTHON) scripts/demo_script.py --write-only

assess-fixture:
	$(PYTHON) agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir $(OUTPUT_DIR)

assess-fixture-agentic:
	$(PYTHON) agent.py assess --provider fixture --scenario scenario_agentic_risk --output-dir $(OUTPUT_AGENTIC)

validate-output-agentic:
	$(PYTHON) scripts/validate_outputs.py --output-dir $(OUTPUT_AGENTIC)

# Observe → plan → act → verify → explain; fixture-only; no cloud remediation (writes trace under OUTPUT_AGENTIC).
validate-agentic-loop:
	$(PYTHON) agent.py run-agent --provider fixture --scenario scenario_agentic_risk \
		--output-dir $(OUTPUT_AGENTIC) --package-output $(OUTPUT_AGENTIC)/agent_run_20x

collect-aws:
	$(PYTHON) scripts/collect_aws_evidence.py --region $(REGION) --output-dir $(RAW_EVIDENCE_DIR) $(if $(strip $(PROFILE)),--profile $(PROFILE),)

assess-aws:
	$(PYTHON) agent.py assess --provider aws --raw-evidence-dir $(RAW_EVIDENCE_DIR) --output-dir $(OUTPUT_DIR)

build-20x:
	$(PYTHON) agent.py build-20x-package --assessment-output $(OUTPUT_DIR) --config $(CONFIG_DIR) --package-output $(dir $(PACKAGE_JSON))

validate-20x:
	$(PYTHON) agent.py validate-20x-package --package $(PACKAGE_JSON) --schemas $(SCHEMAS_DIR)

reports:
	$(PYTHON) agent.py generate-20x-reports --package $(PACKAGE_JSON) --config $(CONFIG_DIR)

reconcile:
	$(PYTHON) agent.py reconcile-20x --package $(PACKAGE_JSON) --reports $(REPORTS_ROOT)

web:
	$(PYTHON) scripts/serve_web.py

# Generated-output safety scan: walks output/, output_tracker/, output_agent_run/,
# evidence/, reports/, web/sample-data/ and FAILs (rc=1) on any non-allowlisted
# secret-shaped or high-risk PII match. Findings print redacted (file:line + first
# 4 chars + "***[redacted len=N]") — full secret values never reach the terminal.
scan-outputs:
	$(PYTHON) scripts/scan_generated_outputs.py

# Reference excerpts vs runtime: manifest, licenses, unknown-license reuse flags, import boundaries.
audit-reference-reuse:
	$(PYTHON) scripts/audit_reference_reuse.py

# Bundle the curated demo-ready artifacts (READMEs, narrative docs, the
# generated 20x package, executive/AO/assessor reports, validation summary,
# and web sample-data) into demo_artifacts.zip + demo_artifacts_manifest.json.
# Runs scripts/scan_generated_outputs.py and scripts/validate_everything.py
# as safety gates first; refuses to package if either reports FAIL.
# Override defaults: make package-demo PACKAGE_DEMO_ARGS="--skip-validation".
PACKAGE_DEMO_ARGS ?=
package-demo:
	$(PYTHON) scripts/package_demo_artifacts.py $(PACKAGE_DEMO_ARGS)

validate-output:
	$(PYTHON) scripts/validate_outputs.py --output-dir $(OUTPUT_DIR)

all: assess-fixture validate-output build-20x validate-20x reports reconcile validate-agentic-loop demo
