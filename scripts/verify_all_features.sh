#!/usr/bin/env bash
# Exhaustive feature verification for observable-security-agent.
#
# Exercises every CLI subcommand, every helper script, the FastAPI explain server,
# the static web server, all 3 fixture scenarios, and Prowler / OCSF importers.
#
# Optional live AWS path: set OS_AGENT_CSV=/path/to/accessKeys.csv  (REGION=us-gov-west-1 by default).
# When OS_AGENT_CSV is set, this script also exercises CSV bootstrap,
# packer run-with-creds --mode validate, live collect, and assess on the live region root.
#
# Run:  bash scripts/verify_all_features.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SI="$(cd "$ROOT/.." && pwd)"
cd "$ROOT"

OUT="$ROOT/output/verify_features"
rm -rf "$OUT"
mkdir -p "$OUT"

PASS_LOG="$OUT/_pass.log"
SKIP_LOG="$OUT/_skip.log"
: >"$PASS_LOG"
: >"$SKIP_LOG"
record_pass() { printf "  PASS  %s\n" "$1" | tee -a "$PASS_LOG"; }
record_skip() { printf "  SKIP  %s : %s\n" "$1" "$2" | tee -a "$SKIP_LOG"; }
section() { printf "\n========== %s ==========\n" "$1"; }

# ---------------------------------------------------------------------------
section "0. Environment"
python3 -V
python3 -c "import pydantic, yaml, jsonschema, boto3; print('imports OK')"
record_pass "env imports"

# ---------------------------------------------------------------------------
section "1. pytest (full)"
python3 -m pytest -q --tb=line 2>&1 | tail -3
record_pass "pytest 332"

# ---------------------------------------------------------------------------
section "2. CLI: list-evals"
python3 agent.py list-evals | tee "$OUT/list_evals.txt" | head -20
test -s "$OUT/list_evals.txt"
record_pass "list-evals"

# ---------------------------------------------------------------------------
section "3. assess: all three fixture scenarios"
for scen in scenario_public_admin_vuln_event scenario_20x_readiness scenario_agentic_risk; do
  od="$OUT/assess_${scen}"
  python3 agent.py assess --provider fixture --scenario "$scen" --output-dir "$od" >"$od.stdout" 2>&1
  test -f "$od/eval_results.json"
  test -f "$od/evidence_graph.json"
  if [[ "$scen" == "scenario_20x_readiness" ]]; then
    # scenario_20x_readiness is the all-PASS green/live-style path; validate it
    # with live semantics so no demo-specific FAIL or POA&M rows are required.
    python3 scripts/validate_outputs.py --output-dir "$od" --mode live >>"$od.stdout" 2>&1
    python3 agent.py validate --output-dir "$od" --mode live >>"$od.stdout" 2>&1
  else
    python3 scripts/validate_outputs.py --output-dir "$od" >>"$od.stdout" 2>&1
    python3 agent.py validate --output-dir "$od" >>"$od.stdout" 2>&1
  fi
  record_pass "assess + validate $scen"
done

# ---------------------------------------------------------------------------
section "4. report: re-render from eval_results.json"
SRC="$OUT/assess_scenario_public_admin_vuln_event"
RPT="$OUT/report_rerender"
mkdir -p "$RPT"
python3 agent.py report --input "$SRC/eval_results.json" --output-dir "$RPT" >"$RPT/stdout" 2>&1
test -f "$RPT/poam.csv"
test -f "$RPT/instrumentation_plan.md"
record_pass "report (re-render)"

# ---------------------------------------------------------------------------
section "5. secure-agent-arch"
SA="$OUT/secure_agent_arch"
python3 agent.py secure-agent-arch --output-dir "$SA"
test -f "$SA/secure_agent_architecture.md"
record_pass "secure-agent-arch"

# ---------------------------------------------------------------------------
section "6. threat-hunt: agentic risk fixture"
TH="$OUT/threat_hunt"
python3 agent.py threat-hunt --provider fixture --scenario scenario_agentic_risk --output-dir "$TH" | tee "$TH.stdout" >/dev/null
test -f "$TH/threat_hunt_findings.json"
test -f "$TH/threat_hunt_timeline.md"
record_pass "threat-hunt (agentic)"

# ---------------------------------------------------------------------------
section "7. run-agent: bounded loop on agentic_risk"
LOOP="$OUT/loop"
python3 agent.py run-agent --provider fixture --scenario scenario_agentic_risk \
  --output-dir "$LOOP" --package-output "$LOOP/agent_run_20x" >"$LOOP.stdout" 2>&1
test -f "$LOOP/agent_run_trace.json"
test -f "$LOOP/agent_run_summary.md"
python3 -c "
import json
d=json.load(open('$LOOP/agent_run_trace.json'))
assert d.get('bounded_playbook') is True
phases={s.get('phase') for s in d.get('steps') or []}
assert {'observe','plan','act','explain'} <= phases, phases
"
record_pass "run-agent (bounded loop)"

# ---------------------------------------------------------------------------
section "8. build-20x-package + validate-20x + reports + reconcile (cloud + agentic)"
for src in assess_scenario_public_admin_vuln_event assess_scenario_agentic_risk; do
  pkg="$OUT/${src#assess_}_pkg20x"
  python3 agent.py build-20x-package --assessment-output "$OUT/$src" --config config --package-output "$pkg" >>"$OUT/${src}_pkg.stdout" 2>&1
  python3 agent.py validate-20x-package --package "$pkg/fedramp20x-package.json" --schemas schemas
  python3 agent.py generate-20x-reports --package "$pkg/fedramp20x-package.json" --config config
  python3 agent.py reconcile-20x --package "$pkg/fedramp20x-package.json" --reports "$pkg" >>"$OUT/${src}_pkg.stdout" 2>&1
  python3 agent.py reconcile-reports --package-output "$pkg" >>"$OUT/${src}_pkg.stdout" 2>&1
  test -f "$pkg/reports/executive/executive-summary.md"
  test -f "$pkg/reports/assessor/assessor-summary.md"
  test -f "$pkg/reports/agency-ao/ao-risk-brief.md"
  record_pass "20x package: $src"
done

# ---------------------------------------------------------------------------
section "9. import-findings (Prowler, OCSF)"
PR="$OUT/import_prowler.json"
OC="$OUT/import_ocsf.json"
python3 agent.py import-findings --format prowler \
  --input tests/fixtures/prowler/prowler_sample_results.json --output "$PR" >>"$OUT/import.stdout" 2>&1
python3 agent.py import-findings --format ocsf \
  --input tests/fixtures/ocsf/sample_detection.json --output "$OC" >>"$OUT/import.stdout" 2>&1
python3 -c "import json; d=json.load(open('$PR')); assert d.get('findings'), 'empty prowler import'"
python3 -c "import json; d=json.load(open('$OC')); assert d.get('findings'), 'empty ocsf import'"
record_pass "import-findings prowler+ocsf"

# ---------------------------------------------------------------------------
section "10. assess --provider aws (fixture-shaped raw dir)"
AWSF="$OUT/assess_aws_fixture"
python3 agent.py assess --provider aws --raw-evidence-dir "$ROOT/fixtures/scenario_public_admin_vuln_event" \
  --output-dir "$AWSF" >"$AWSF.stdout" 2>&1
python3 scripts/validate_outputs.py --output-dir "$AWSF"
record_pass "assess --provider aws (fixture-shaped)"

# ---------------------------------------------------------------------------
section "11. scripts/run_fixture_assessment.py"
python3 scripts/run_fixture_assessment.py >"$OUT/run_fixture.stdout" 2>&1
record_pass "run_fixture_assessment.py"

# ---------------------------------------------------------------------------
section "12. scripts/run_aws_assessment.py (fixture-shaped)"
RAA="$OUT/run_aws_assessment"
python3 scripts/run_aws_assessment.py --evidence-dir "$ROOT/fixtures/scenario_public_admin_vuln_event" \
  --output-dir "$RAA" >"$RAA.stdout" 2>&1
test -f "$RAA/eval_results.json"
record_pass "run_aws_assessment.py"

# ---------------------------------------------------------------------------
section "13. scripts/export_graph_cypher.py"
CY="$OUT/evidence_graph.cypher"
python3 scripts/export_graph_cypher.py --input "$AWSF/evidence_graph.json" --output "$CY"
test -s "$CY"
grep -q MERGE "$CY"
record_pass "export_graph_cypher.py"

# ---------------------------------------------------------------------------
section "14. scripts/demo_script.py (write-only)"
python3 scripts/demo_script.py --write-only >/dev/null
test -f "$ROOT/output/demo_walkthrough.md"
record_pass "demo_script.py"

# ---------------------------------------------------------------------------
section "15. scripts/buildlab_readiness.py"
python3 scripts/buildlab_readiness.py 2>&1 | tail -3
test -f "$ROOT/output/buildlab_readiness.md"
record_pass "buildlab_readiness.py"

# ---------------------------------------------------------------------------
section "16a. Agentic event coverage (tool_calls / memory_events / policy_violations / identities → eval grid)"
python3 - <<'PY'
"""Confirm every agentic-AI event class in scenario_agentic_risk drives a corresponding eval row."""
import json
from pathlib import Path

scen = Path("fixtures/scenario_agentic_risk")
needed_inputs = [
    "agent_identities.json",
    "agent_tool_calls.json",
    "agent_memory_events.json",
    "agent_policy_violations.json",
]
for n in needed_inputs:
    assert (scen / n).is_file(), f"missing fixture {n}"

ev = json.loads(Path("output/verify_features/assess_scenario_agentic_risk/eval_results.json").read_text())
rows = {r.get("eval_id"): r for r in ev.get("evaluations") or []}
required_evals = {
    "AGENT_TOOL_GOVERNANCE",
    "AGENT_PERMISSION_SCOPE",
    "AGENT_MEMORY_CONTEXT_SAFETY",
    "AGENT_APPROVAL_GATES",
    "AGENT_POLICY_VIOLATIONS",
    "AGENT_AUDITABILITY",
}
missing = required_evals - rows.keys()
assert not missing, f"agent eval rows missing: {missing}"
fails = {k for k in required_evals if str(rows[k].get("result", "")).upper() in {"FAIL", "PARTIAL"}}
assert fails, "agentic_risk fixture should produce at least one FAIL/PARTIAL agent eval"
# Each row must cite the agent fixture inputs (no invented evidence).
for eid in required_evals:
    used = json.dumps(rows[eid]).lower()
    assert "agent" in used, f"eval {eid} did not reference agent_* evidence"
print("agent event classes mapped → eval rows:", sorted(required_evals))
print("FAIL/PARTIAL agent rows:", sorted(fails))
PY
record_pass "agentic event classes → eval rows"

section "16b. Threat hunt findings cover agentic categories with evidence_refs"
python3 - <<'PY'
import json
from pathlib import Path

doc = json.loads(Path("output/verify_features/threat_hunt/threat_hunt_findings.json").read_text())
items = doc.get("findings") or []
assert len(items) >= 3, f"expected >=3 hunt findings, got {len(items)}"
detection_types = {str(it.get("detection_type", "")).lower() for it in items}
expected_any = {
    "shadow_ai_usage", "prompt_injection_suspected", "compromised_agent_behavior",
    "unauthorized_credential_use", "privilege_escalation_via_automation",
    "agent_acting_outside_intended_permissions",
}
hits = {d for d in detection_types if any(e in d for e in expected_any)}
assert hits, f"no hunt findings matched expected agentic categories; got {sorted(detection_types)}"
# Every finding must cite at least one evidence_ref into agent_*.json fixtures (no invented narrative).
no_refs = [it for it in items if not it.get("evidence_refs")]
assert not no_refs, f"hunt findings without evidence_refs: {no_refs}"
print("hunt detection types:", sorted(detection_types))
print(f"finding_count={doc.get('finding_count')} all carry evidence_refs")
PY
record_pass "threat-hunt covers agentic categories"

section "16c. Bounded loop multi-task split (>=8 act steps; policy decisions logged)"
python3 - <<'PY'
import json
from pathlib import Path

t = json.loads(Path("output/verify_features/loop/agent_run_trace.json").read_text())
steps = t.get("steps") or []
phases = [s.get("phase") for s in steps]
acts = [s for s in steps if s.get("phase") == "act"]
chosen = [s.get("chosen_action") for s in acts]
required_actions = {
    "assess_run_evals",
    "threat_hunt_agentic",
    "normalize_findings",
    "generate_instrumentation_recommendations",
    "generate_poam_drafts",
    "draft_tickets_json_only",
    "build_20x_package",
    "validate_assessment_outputs",
    "validate_20x_package",
    "reconcile_20x_reports",
}
missing = required_actions - set(chosen)
assert not missing, f"bounded loop did not run actions: {missing}"
# Every step must include a policy decision (allow/deny) — no silent execution.
no_policy = [s for s in steps if not s.get("policy")]
assert not no_policy, f"steps without policy decision: {[s.get('chosen_action') for s in no_policy]}"
# Blocked categories cited (ensures the loop is bounded).
assert {b.get("id") for b in t.get("blocked_categories_reference") or []} >= {
    "cloud_modification", "permission_change", "destructive_change",
    "external_notification", "real_ticket_create",
}, "blocked_categories_reference incomplete"
print(f"act steps: {len(acts)} / phases: {sorted(set(phases))}")
print(f"all required actions present: True")
PY
record_pass "run-agent multi-task split + policy decisions logged"

section "16. api/explain (deterministic LLM-free explain)"
python3 - <<'PY'
import json
from pathlib import Path
from api.explain import run_explain

ev = json.loads(Path("output/verify_features/assess_scenario_public_admin_vuln_event/eval_results.json").read_text())
rows = ev.get("evaluations") or []
for mode in ("explain_eval", "trace_derivation"):
    pick = next(r for r in rows if str(r.get("result","")).upper() == "FAIL")
    out = run_explain(
        mode=mode, question="Trace from evidence only.", audience="assessor",
        selected_eval=pick, related_evidence=None, related_graph=None,
        related_poam=[], fedramp20x_context=None,
    )
    ans = out.get("answer", "")
    assert "Evidence contract" in ans, f"no contract footer ({mode})"
print("explain_eval + trace_derivation OK")
PY
record_pass "api.explain modes"

# ---------------------------------------------------------------------------
section "16d. LLM-backed explain (mocked OpenAI-compatible HTTP)"
python3 - <<'PY'
"""Exercise call_openai_compatible by stubbing httpx; confirm grounded prompt + LLM answer wiring."""
import importlib
import json
import os
from pathlib import Path
import sys

os.environ["AI_API_KEY"] = "test-key-not-secret"
os.environ["AI_MODEL"] = "test-model"
os.environ["AI_API_BASE"] = "https://api.example.invalid/v1"

# Reload api.explain so it picks env vars.
sys.modules.pop("api.explain", None)
api_explain = importlib.import_module("api.explain")

import httpx

captured: dict = {}


def handler(request: httpx.Request) -> httpx.Response:
    captured["url"] = str(request.url)
    captured["model_in_body"] = "test-model" in request.content.decode("utf-8", "ignore")
    captured["has_grounded_preamble"] = "evidence" in request.content.decode("utf-8", "ignore").lower()
    return httpx.Response(
        200,
        json={
            "choices": [
                {"message": {"role": "assistant", "content": "MOCK-LLM ANSWER (cited eval_results.json only)."}}
            ]
        },
    )


orig_client = httpx.Client


class _MockClient(orig_client):
    def __init__(self, *a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        super().__init__(*a, **kw)


httpx.Client = _MockClient
try:
    ev = json.loads(
        Path("output/verify_features/assess_scenario_public_admin_vuln_event/eval_results.json").read_text()
    )
    pick = next(r for r in (ev.get("evaluations") or []) if str(r.get("result", "")).upper() == "FAIL")
    out = api_explain.run_explain(
        mode="explain_eval",
        question="Why FAIL?",
        audience="assessor",
        selected_eval=pick,
        related_evidence=None,
        related_graph=None,
        related_poam=[],
        fedramp20x_context=None,
    )
finally:
    httpx.Client = orig_client

assert "MOCK-LLM" in out["answer"], f"LLM answer missing: {out!r}"
assert "llm" in out["used_artifacts"], f"used_artifacts should include 'llm', got {out['used_artifacts']}"
assert captured.get("model_in_body"), "AI_MODEL env not used in payload"
assert captured.get("url", "").endswith("/chat/completions"), f"unexpected URL: {captured.get('url')}"
print("LLM-backed explain wiring: OK")

# Also verify failure path (5xx) gracefully falls back to deterministic + warning.
def handler_500(request):
    return httpx.Response(500, json={"error": "boom"})


class _MockBadClient(orig_client):
    def __init__(self, *a, **kw):
        kw["transport"] = httpx.MockTransport(handler_500)
        super().__init__(*a, **kw)


httpx.Client = _MockBadClient
try:
    out_bad = api_explain.run_explain(
        mode="trace_derivation",
        question="Why FAIL?",
        audience="assessor",
        selected_eval=pick,
        related_evidence=None,
        related_graph=None,
        related_poam=[],
        fedramp20x_context=None,
    )
finally:
    httpx.Client = orig_client
assert "Evidence contract" in out_bad["answer"], "deterministic footer missing on LLM failure"
assert any("LLM unavailable" in w for w in out_bad.get("warnings") or []), out_bad.get("warnings")
print("LLM failure → deterministic fallback + warning: OK")
PY
record_pass "LLM call wiring (mocked) + graceful fallback"

section "17. api/server (FastAPI POST /api/explain — best effort)"
if python3 -c "import fastapi, httpx, uvicorn" >/dev/null 2>&1; then
  python3 - <<'PY'
import json, time, threading, urllib.request
from pathlib import Path

import uvicorn
from api.server import app

cfg = uvicorn.Config(app, host="127.0.0.1", port=8181, log_level="warning")
server = uvicorn.Server(cfg)
t = threading.Thread(target=server.run, daemon=True)
t.start()
deadline = time.time() + 5
while time.time() < deadline:
    try:
        urllib.request.urlopen("http://127.0.0.1:8181/api/health", timeout=1).read()
        break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("api server did not start")

ev = json.loads(Path("output/verify_features/assess_scenario_public_admin_vuln_event/eval_results.json").read_text())
pick = next(r for r in (ev.get("evaluations") or []) if str(r.get("result","")).upper() == "FAIL")
body = json.dumps({"mode": "trace_derivation", "selected_eval": pick, "audience": "assessor"}).encode("utf-8")
req = urllib.request.Request(
    "http://127.0.0.1:8181/api/explain",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
res = urllib.request.urlopen(req, timeout=5)
data = json.loads(res.read().decode("utf-8"))
assert "Evidence contract" in (data.get("answer") or ""), "no contract footer in HTTP response"
server.should_exit = True
t.join(timeout=3)
print("api.server /api/health + /api/explain: OK")
PY
  record_pass "api/server in-process"
else
  record_skip "api/server" "fastapi/uvicorn not installed (pip install -e '.[api]')"
fi

# ---------------------------------------------------------------------------
section "18. scripts/serve_web.py (HTTP serve check)"
python3 - <<'PY'
import os, sys, time, threading, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path("scripts").resolve()))

import functools, http.server, socketserver

root = Path.cwd()
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
handler = functools.partial(H, directory=str(root))
httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
port = httpd.server_address[1]
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
try:
    for path in ("/web/index.html", "/web/app.js", "/web/styles.css", "/web/sample-data/eval_results.json", "/web/sample-data/agent_run_trace.json"):
        url = f"http://127.0.0.1:{port}{path}"
        r = urllib.request.urlopen(url, timeout=2)
        assert r.status == 200, f"{url} {r.status}"
    print(f"static web serve on :{port} OK")
finally:
    httpd.shutdown()
PY
record_pass "static web (web/index + sample-data)"

# ---------------------------------------------------------------------------
section "19. Optional: live AWS via CSV bootstrap"
if [[ -n "${OS_AGENT_CSV:-}" && -f "${OS_AGENT_CSV}" ]]; then
  REGION="${REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-us-gov-west-1}}}"
  TMP="$(mktemp -d "${TMPDIR:-/tmp}/os_agent_full_verify_XXXXXX")"
  CREDS="$TMP/creds.json"
  SRC="$TMP/creds.source.json"
  trap 'rm -rf "$TMP"' EXIT

  echo "  bootstrapping CSV -> $TMP (region=$REGION)..."
  bash "$SI/infrastructure/packer/bootstrap-creds-json-from-csv.sh" \
    --csv-file "$OS_AGENT_CSV" --creds-file "$CREDS" --source-creds-file "$SRC" --region "$REGION" >/dev/null
  record_pass "bootstrap-creds-json-from-csv.sh"

  echo "  packer run-with-creds.sh --mode validate ..."
  ( cd "$SI/infrastructure/packer" && \
    SECURITY_CREDS_FILE="$CREDS" SECURITY_SOURCE_CREDS_FILE="$SRC" SECURITY_AWS_REGION="$REGION" \
      ./run-with-creds.sh --mode validate --region "$REGION" 2>&1 | tail -2 )
  record_pass "run-with-creds.sh validate (18 templates)"

  eval "$(python3 "$ROOT/scripts/export_aws_session_env.py" "$CREDS")"
  export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

  python3 -c "import boto3; i=boto3.client('sts').get_caller_identity(); a=str(i.get('Account','')); m=('*'*(len(a)-4)+a[-4:]) if len(a)>4 else '****'; print('  STS:', m, str(i.get('Arn','')).replace(a, m))"
  record_pass "STS get-caller-identity"

  LIVE_OUT="$(mktemp -d "${TMPDIR:-/tmp}/os_agent_verify_live_out_XXXXXX")"
  trap 'rm -rf "$TMP" "$LIVE_OUT"' EXIT
  RAW="$LIVE_OUT/raw"
  mkdir -p "$RAW"
  python3 scripts/collect_aws_evidence.py --region "$REGION" --output-dir "$RAW" --fixture-compatible >"$LIVE_OUT/live_collect.stdout" 2>&1
  EVD=$(RAW="$RAW" python3 -c "
from pathlib import Path
import os
for p in Path(os.environ['RAW']).rglob('manifest.json'):
    print(p.parent); break
")
  test -n "$EVD"
  test -f "$EVD/cloud_events.json"
  record_pass "collect_aws_evidence (region=$REGION)"

  AWSL="$LIVE_OUT/assess_aws_live"
  python3 agent.py assess --provider aws --raw-evidence-dir "$EVD" --output-dir "$AWSL" --mode live >"$LIVE_OUT/assess_aws_live.stdout" 2>&1
  python3 scripts/validate_outputs.py --output-dir "$AWSL" --mode live
  record_pass "assess-aws on live raw + validate_outputs"

  python3 agent.py threat-hunt --provider aws --raw-evidence-dir "$EVD" --output-dir "$LIVE_OUT/threat_hunt_aws" >>"$LIVE_OUT/live_collect.stdout" 2>&1
  test -f "$LIVE_OUT/threat_hunt_aws/threat_hunt_findings.json"
  record_pass "threat-hunt --provider aws (live raw)"
else
  record_skip "live AWS" "set OS_AGENT_CSV=/path/to/accessKeys.csv (and optional REGION) to exercise CSV→creds→collect→assess"
fi

# ---------------------------------------------------------------------------
section "DONE"
echo "PASS rows:"
cat "$PASS_LOG"
echo ""
echo "SKIP rows:"
cat "$SKIP_LOG" || true
