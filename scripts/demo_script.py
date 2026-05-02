#!/usr/bin/env python3
"""
Print a BuildLab-friendly live-demo script and write ``output/demo_walkthrough.md``.

Run from the observable-security-agent repo root (directory containing ``agent.py``).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


TAGLINE = (
    "Most tools detect misconfigurations. This evaluates whether the security program is observable, "
    "instrumented, correlated, and audit-ready."
)

# Sponsor / BuildLab: bounded autonomy (deterministic pipeline + optional explain), not ungoverned agents.
BOUNDED_AUTONOMY = (
    "Autonomy is bounded: the agent runs a fixed evaluation pipeline over an explicit evidence bundle and "
    "optional read-only explain endpoints—no ungoverned tool loops or silent mutation of your cloud."
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def build_walkthrough(
    *,
    root: Path,
    scenario: str,
    output_dir: str,
    package_dir: str,
    config_dir: str,
    schemas_dir: str,
) -> str:
    """Return markdown for the demo script (same content printed to stdout)."""
    pkg = Path(package_dir)
    out = Path(output_dir)
    rel_pkg = pkg.as_posix()
    rel_out = out.as_posix()
    rel_cfg = Path(config_dir).as_posix()
    rel_sch = Path(schemas_dir).as_posix()
    pkg_json = f"{rel_pkg}/fedramp20x-package.json"

    lines: list[str] = [
        "# Observable Security Agent — BuildLab live demo",
        "",
        TAGLINE,
        "",
        BOUNDED_AUTONOMY,
        "",
        "---",
        "",
        "## 1. Setup",
        "",
        "From the **observable-security-agent** repository root (the directory that contains `agent.py`, `config/`, and `fixtures/`):",
        "",
        "```bash",
        "cd <path-to-observable-security-agent>",
        "python3 -m venv .venv",
        "source .venv/bin/activate  # Windows: .venv\\Scripts\\activate",
        "pip install -r requirements.txt",
        "```",
        "",
        "---",
        "",
        "## 2. Run assessment",
        "",
        f"Ingest fixture evidence, normalize the primary event, run all evaluations, and emit artifacts under `{rel_out}/`.",
        "",
        "```bash",
        "python agent.py assess \\",
        "  --provider fixture \\",
        f"  --scenario {scenario} \\",
        f"  --output-dir {rel_out}",
        "```",
        "",
        "**You should see:** mixed `PASS` / `PARTIAL` / `FAIL` lines plus paths to `eval_results.json`, `evidence_graph.json`, and `correlations.json`.",
        "",
        "---",
        "",
        "## 3. Explain the evidence graph",
        "",
        "The graph links declared inventory, discovered assets, scanner targets, findings, events, log sources, alert rules, and tickets — the same object model assessors trace in an evidence interview.",
        "",
        "```bash",
        f"python -m json.tool {rel_out}/evidence_graph.json | head -n 80",
        "```",
        "",
        "Optional: open `output/evidence_graph.json` in your editor and search for `edges` / `relationship`.",
        "",
        "---",
        "",
        "## 4. Show a failed or stressed correlated event",
        "",
        "`correlations.json` is written by the cross-domain correlation eval. Inspect rows where the chain is incomplete:",
        "",
        "```bash",
        f"python -m json.tool {rel_out}/correlations.json | head -n 120",
        "```",
        "",
        "Narration hook: *\"This row is the assessor view — not just that something happened, but whether inventory, scanning, logging, alerting, and ticketing all line up.\"*",
        "",
        "---",
        "",
        "## 5. Show derivation trace (deterministic explain)",
        "",
        "Grounded derivation text (no API key required) lives in `api/explain.py`. Example: trace why inventory or exploitation evals failed using the bundled rules:",
        "",
        "```bash",
        "python <<'PY'",
        "import json",
        "from pathlib import Path",
        "from api.explain import run_explain",
        f"p = json.loads(Path('{rel_out}/eval_results.json').read_text())",
        "rows = p.get('evaluations') or []",
        "def is_fail(r): return str(r.get('result', '')).upper() == 'FAIL'",
        "pick = next((r for r in rows if is_fail(r)), rows[0] if rows else {})",
        "out = run_explain(",
        "    mode='trace_derivation',",
        "    question='Walk the derivation from evidence to this result.',",
        "    selected_eval=pick,",
        "    related_evidence=None,",
        "    related_graph=None,",
        "    related_poam=[],",
        ")",
        "print(out.get('answer', ''))",
        "PY",
        "```",
        "",
        "Human-readable narrative: skim `output/correlation_report.md` for the same run.",
        "",
        "---",
        "",
        "## 6. Generate FedRAMP 20x package",
        "",
        "Roll eval outcomes into KSI validation rows, findings, POA&M linkage, reconciliation snapshot, and human reports under the package tree.",
        "",
        "```bash",
        "python agent.py build-20x-package \\",
        f"  --assessment-output {rel_out} \\",
        f"  --config {rel_cfg} \\",
        f"  --package-output {rel_pkg}",
        "```",
        "",
        "---",
        "",
        "## 7. Validate package schema",
        "",
        "```bash",
        "python agent.py validate-20x-package \\",
        f"  --package {pkg_json} \\",
        f"  --schemas {rel_sch}",
        "```",
        "",
        "**Expect:** `VALIDATION PASSED` (or actionable schema errors if the package JSON was hand-edited).",
        "",
        "---",
        "",
        "## 8. Show KSI dashboard",
        "",
        "Executive bundle includes the posture dashboard (KSI rollup at a glance):",
        "",
        "```bash",
        f"sed -n '1,120p' {rel_pkg}/reports/executive/security-posture-dashboard.md",
        "```",
        "",
        "**Optional UI:** `python scripts/serve_web.py` → open `http://127.0.0.1:8080/web/index.html` → **FedRAMP 20x → 20x package dashboard** and **KSI explorer**.",
        "",
        "---",
        "",
        "## 8a. Bounded autonomous loop (observe → plan → act → verify → explain)",
        "",
        "Fixture-only orchestration: runs assess, threat-hunt stubs, normalization, 20x package build/validate, reconciliation, and writes **`agent_run_trace.json`** / **`agent_run_summary.md`** — no cloud remediation, no external tickets.",
        "",
        "```bash",
        "python agent.py run-agent \\",
        "  --provider fixture \\",
        "  --scenario scenario_agentic_risk \\",
        "  --output-dir output_agentic \\",
        "  --package-output output_agentic/agent_run_20x",
        "```",
        "",
        "In the Explorer: **Agent run trace** panel loads the trace JSON and summary.",
        "",
        "---",
        "",
        "## 9. Show assessor report",
        "",
        "```bash",
        f"sed -n '1,120p' {rel_pkg}/reports/assessor/assessor-summary.md",
        "```",
        "",
        "---",
        "",
        "## 10. Show executive report",
        "",
        "```bash",
        f"sed -n '1,100p' {rel_pkg}/reports/executive/executive-summary.md",
        "```",
        "",
        "---",
        "",
        "## 11. Show AO risk brief",
        "",
        "```bash",
        f"sed -n '1,120p' {rel_pkg}/reports/agency-ao/ao-risk-brief.md",
        "```",
        "",
        "---",
        "",
        "## 12. Show reconciliation",
        "",
        "Package-level parity and counts:",
        "",
        "```bash",
        f"cat {rel_pkg}/reports/reconciliation_report.md",
        "```",
        "",
        "Deep reconciliation artifacts (when generated alongside the package):",
        "",
        "```bash",
        f"ls -la {rel_pkg}/reports/assessor/reconciliation-summary.md 2>/dev/null || true",
        "```",
        "",
        "---",
        "",
        "## 13. Show AI explanation panel",
        "",
        "1. **Web UI:** With `python scripts/serve_web.py` running, open **AI explain** in the left nav (`#ai`).",
        "2. **API:** In another terminal: `python -m uvicorn api.server:app --reload --port 8081` (if you added the API extra), then the web UI calls `POST /api/explain`.",
        "3. **CLI (deterministic):** reuse the `run_explain` one-liner in §5 with `mode='explain_ksi'` or `explain_eval` and JSON from `fedramp20x-package.json`.",
        "",
        "---",
        "",
        "## 14. Close — product positioning",
        "",
        TAGLINE,
        "",
        BOUNDED_AUTONOMY,
        "",
        "Use this line when wrapping: *misconfiguration scanners answer \"what is wrong in the cloud configuration\"; this agent answers \"can we prove the security program operates end-to-end for this boundary.\"*",
        "",
        "---",
        "",
        f"_Generated for scenario `{scenario}`. Re-run: `python scripts/demo_script.py`_",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Print BuildLab demo script and write output/demo_walkthrough.md")
    parser.add_argument(
        "--scenario",
        default="scenario_20x_readiness",
        help="Fixture scenario name under fixtures/ (default: scenario_20x_readiness)",
    )
    parser.add_argument("--output-dir", default="output", help="Assessment output directory (default: output)")
    parser.add_argument(
        "--package-dir",
        default="evidence/package",
        help="FedRAMP 20x package output directory (default: evidence/package)",
    )
    parser.add_argument("--config-dir", default="config", help="Config directory for build-20x-package (default: config)")
    parser.add_argument("--schemas-dir", default="schemas", help="JSON Schema directory (default: schemas)")
    parser.add_argument(
        "--write-only",
        action="store_true",
        help="Write output/demo_walkthrough.md only; do not print to stdout",
    )
    args = parser.parse_args()

    root = _repo_root()
    text = build_walkthrough(
        root=root,
        scenario=args.scenario,
        output_dir=args.output_dir,
        package_dir=args.package_dir,
        config_dir=args.config_dir,
        schemas_dir=args.schemas_dir,
    )

    out_md = root / args.output_dir / "demo_walkthrough.md"
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(text, encoding="utf-8")

    if not args.write_only:
        print(text, end="")
    else:
        print(f"Wrote {out_md}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
