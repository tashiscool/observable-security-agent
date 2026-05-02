#!/usr/bin/env bash
# Full demo verification for observable-security-agent (fixtures + 20x + bounded loop + BuildLab harness).
# Run from repo root:  bash scripts/verify_demo.sh
#
# AWS access-key CSV (repo parent): refresh creds without committing secrets:
#   bash ../infrastructure/packer/bootstrap-creds-json-from-csv.sh --csv-file /path/to/accessKeys.csv
# Optional live read-only collection (region from env, or load session JSON first):
#   export OS_AGENT_CREDS_JSON=/path/to/creds.json   # STS session file from bootstrap-creds-json-from-csv.sh
#   export AWS_REGION=us-gov-west-1
#   make verify-demo
# Or: make aws-bootstrap-verify CSV_FILE=/path/to/accessKeys.csv
# Companion JSON is written next to manifest.json under raw/aws/{account}/{region}/ when using --fixture-compatible.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "========== pytest =========="
python3 -m pytest -q --tb=no

echo ""
echo "========== make all =========="
rm -rf output output_agentic evidence/package
make all

echo ""
echo "========== buildlab_readiness =========="
python3 scripts/buildlab_readiness.py

echo ""
echo "========== run_fixture_assessment.py =========="
python3 scripts/run_fixture_assessment.py

echo ""
echo "========== bounded loop + cloud + threat + 20x + explain =========="
VERIFY_ROOT="${VERIFY_ROOT:-output/verify_demo_run}"
VERIFY_ABS="$ROOT/$VERIFY_ROOT"
rm -rf "$VERIFY_ABS"
mkdir -p "$VERIFY_ABS"
python3 agent.py run-agent --provider fixture --scenario scenario_agentic_risk \
  --output-dir "$VERIFY_ABS/loop" --package-output "$VERIFY_ABS/loop/agent_run_20x"
python3 agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event \
  --output-dir "$VERIFY_ABS/cloud"
python3 agent.py threat-hunt --provider fixture --scenario scenario_agentic_risk \
  --output-dir "$VERIFY_ABS/threat"
python3 scripts/validate_outputs.py --output-dir "$VERIFY_ABS/cloud"
python3 agent.py build-20x-package --assessment-output "$VERIFY_ABS/cloud" --config config \
  --package-output "$VERIFY_ABS/pkg20x"
python3 agent.py validate-20x-package --package "$VERIFY_ABS/pkg20x/fedramp20x-package.json" --schemas schemas
python3 <<PY
import json
from pathlib import Path

from api.explain import run_explain

ev_path = Path("${VERIFY_ABS}/cloud/eval_results.json")
ev = json.loads(ev_path.read_text(encoding="utf-8"))
pick = next(x for x in ev["evaluations"] if x.get("eval_id") == "CROSS_DOMAIN_EVENT_CORRELATION")
ans = run_explain(
    mode="trace_derivation",
    question="Trace from evidence only.",
    audience="assessor",
    selected_eval=pick,
    related_evidence=None,
    related_graph=None,
    related_poam=[],
    fedramp20x_context=None,
)["answer"]
assert "Evidence contract" in ans
print("explain trace_derivation: OK")
PY

echo ""
echo "========== AWS provider layout (fixture directory as raw bundle; no live API) =========="
# Mirrors tests/test_agent_cli.py::test_assess_aws_with_raw_evidence_dir_fixture_layout
python3 agent.py assess --provider aws --raw-evidence-dir "$ROOT/fixtures/scenario_public_admin_vuln_event" \
  --output-dir "$VERIFY_ABS/aws_fixture_layout"
python3 scripts/validate_outputs.py --output-dir "$VERIFY_ABS/aws_fixture_layout"
echo "assess --provider aws with fixture-shaped raw dir: OK"

echo ""
echo "========== optional live AWS collect + assess (best-effort) =========="
if [[ -n "${OS_AGENT_CREDS_JSON:-}" && -f "${OS_AGENT_CREDS_JSON}" ]]; then
  echo "Loading AWS session from OS_AGENT_CREDS_JSON (not printing secrets)."
  eval "$(python3 "$ROOT/scripts/export_aws_session_env.py" "$OS_AGENT_CREDS_JSON")"
  export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-$AWS_REGION}"
fi
if python3 -c "import boto3; boto3.client('sts').get_caller_identity()" >/dev/null 2>&1; then
  RAW_LIVE="$(mktemp -d "${TMPDIR:-/tmp}/os_agent_live_XXXXXX")"
  REG="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
  set +e
  python3 scripts/collect_aws_evidence.py --region "$REG" --output-dir "$RAW_LIVE" --fixture-compatible
  COLL_RC=$?
  set -e
  if [[ "$COLL_RC" -ne 0 ]]; then
    echo "collect_aws_evidence: exit $COLL_RC (skipped downstream assess)"
  else
    # Avoid `find | head` under `set -o pipefail` (SIGPIPE can nonzero-exit the pipeline on macOS).
    EVD="$(RAW_LIVE="$RAW_LIVE" python3 -c "
from pathlib import Path
import os
r = Path(os.environ['RAW_LIVE'])
for p in r.rglob('manifest.json'):
    print(p.parent)
    break
")"
    if [[ -z "$EVD" ]]; then
      echo "collect_aws_evidence: no manifest (skipped assess-aws)"
    else
      set +e
      python3 agent.py assess --provider aws --raw-evidence-dir "$EVD" --output-dir "$VERIFY_ABS/aws_live_collect"
      AR=$?
      set -e
      if [[ "$AR" -eq 0 ]]; then
        python3 scripts/validate_outputs.py --output-dir "$VERIFY_ABS/aws_live_collect"
        echo "live collect + assess-aws + validate_outputs: OK"
      else
        echo "assess-aws on live collect dir: exit $AR (expected if bundle has no cloud_events.json, etc.)"
      fi
    fi
  fi
  rm -rf "$RAW_LIVE"
else
  echo "No default AWS credentials (STS); skipped live collect."
  echo "CSV bootstrap (run from security-infra repo root):"
  echo "  bash infrastructure/packer/bootstrap-creds-json-from-csv.sh --csv-file /path/to/accessKeys.csv"
fi

echo ""
echo "========== ALL VERIFY STEPS COMPLETE =========="
