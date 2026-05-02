# Observable Security Agent — BuildLab live demo

Most tools detect misconfigurations. This evaluates whether the security program is observable, instrumented, correlated, and audit-ready.

Autonomy is bounded: the agent runs a fixed evaluation pipeline over an explicit evidence bundle and optional read-only explain endpoints—no ungoverned tool loops or silent mutation of your cloud.

---

## 1. Setup

From the **observable-security-agent** repository root (the directory that contains `agent.py`, `config/`, and `fixtures/`):

```bash
cd <path-to-observable-security-agent>
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 2. Run assessment

Ingest fixture evidence, normalize the primary event, run all evaluations, and emit artifacts under `output/`.

```bash
python agent.py assess \
  --provider fixture \
  --scenario scenario_20x_readiness \
  --output-dir output
```

**You should see:** mixed `PASS` / `PARTIAL` / `FAIL` lines plus paths to `eval_results.json`, `evidence_graph.json`, and `correlations.json`.

---

## 3. Explain the evidence graph

The graph links declared inventory, discovered assets, scanner targets, findings, events, log sources, alert rules, and tickets — the same object model assessors trace in an evidence interview.

```bash
python -m json.tool output/evidence_graph.json | head -n 80
```

Optional: open `output/evidence_graph.json` in your editor and search for `edges` / `relationship`.

---

## 4. Show a failed or stressed correlated event

`correlations.json` is written by the cross-domain correlation eval. Inspect rows where the chain is incomplete:

```bash
python -m json.tool output/correlations.json | head -n 120
```

Narration hook: *"This row is the assessor view — not just that something happened, but whether inventory, scanning, logging, alerting, and ticketing all line up."*

---

## 5. Show derivation trace (deterministic explain)

Grounded derivation text (no API key required) lives in `api/explain.py`. Example: trace why inventory or exploitation evals failed using the bundled rules:

```bash
python <<'PY'
import json
from pathlib import Path
from api.explain import run_explain
p = json.loads(Path('output/eval_results.json').read_text())
rows = p.get('evaluations') or []
def is_fail(r): return str(r.get('result', '')).upper() == 'FAIL'
pick = next((r for r in rows if is_fail(r)), rows[0] if rows else {})
out = run_explain(
    mode='trace_derivation',
    question='Walk the derivation from evidence to this result.',
    selected_eval=pick,
    related_evidence=None,
    related_graph=None,
    related_poam=[],
)
print(out.get('answer', ''))
PY
```

Human-readable narrative: skim `output/correlation_report.md` for the same run.

---

## 6. Generate FedRAMP 20x package

Roll eval outcomes into KSI validation rows, findings, POA&M linkage, reconciliation snapshot, and human reports under the package tree.

```bash
python agent.py build-20x-package \
  --assessment-output output \
  --config config \
  --package-output evidence/package
```

---

## 7. Validate package schema

```bash
python agent.py validate-20x-package \
  --package evidence/package/fedramp20x-package.json \
  --schemas schemas
```

**Expect:** `VALIDATION PASSED` (or actionable schema errors if the package JSON was hand-edited).

---

## 8. Show KSI dashboard

Executive bundle includes the posture dashboard (KSI rollup at a glance):

```bash
sed -n '1,120p' evidence/package/reports/executive/security-posture-dashboard.md
```

**Optional UI:** `python scripts/serve_web.py` → open `http://127.0.0.1:8080/web/index.html` → **FedRAMP 20x → 20x package dashboard** and **KSI explorer**.

---

## 8a. Bounded autonomous loop (observe → plan → act → verify → explain)

Fixture-only orchestration: runs assess, threat-hunt stubs, normalization, 20x package build/validate, reconciliation, and writes **`agent_run_trace.json`** / **`agent_run_summary.md`** — no cloud remediation, no external tickets.

```bash
python agent.py run-agent \
  --provider fixture \
  --scenario scenario_agentic_risk \
  --output-dir output_agentic \
  --package-output output_agentic/agent_run_20x
```

In the Explorer: **Agent run trace** panel loads the trace JSON and summary.

---

## 9. Show assessor report

```bash
sed -n '1,120p' evidence/package/reports/assessor/assessor-summary.md
```

---

## 10. Show executive report

```bash
sed -n '1,100p' evidence/package/reports/executive/executive-summary.md
```

---

## 11. Show AO risk brief

```bash
sed -n '1,120p' evidence/package/reports/agency-ao/ao-risk-brief.md
```

---

## 12. Show reconciliation

Package-level parity and counts:

```bash
cat evidence/package/reports/reconciliation_report.md
```

Deep reconciliation artifacts (when generated alongside the package):

```bash
ls -la evidence/package/reports/assessor/reconciliation-summary.md 2>/dev/null || true
```

---

## 13. Show AI explanation panel

1. **Web UI:** With `python scripts/serve_web.py` running, open **AI explain** in the left nav (`#ai`).
2. **API:** In another terminal: `python -m uvicorn api.server:app --reload --port 8081` (if you added the API extra), then the web UI calls `POST /api/explain`.
3. **CLI (deterministic):** reuse the `run_explain` one-liner in §5 with `mode='explain_ksi'` or `explain_eval` and JSON from `fedramp20x-package.json`.

---

## 14. Close — product positioning

Most tools detect misconfigurations. This evaluates whether the security program is observable, instrumented, correlated, and audit-ready.

Autonomy is bounded: the agent runs a fixed evaluation pipeline over an explicit evidence bundle and optional read-only explain endpoints—no ungoverned tool loops or silent mutation of your cloud.

Use this line when wrapping: *misconfiguration scanners answer "what is wrong in the cloud configuration"; this agent answers "can we prove the security program operates end-to-end for this boundary."*

---

_Generated for scenario `scenario_20x_readiness`. Re-run: `python scripts/demo_script.py`_
