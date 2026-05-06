#!/usr/bin/env python3
"""
BuildLab readiness harness: environment, fixture demos, 20x package, static web,
optional live cloud, and submission checks.

Writes ``output/buildlab_readiness.md``. Exit 0 when fixture + package + web
readiness pass; missing cloud credentials are WARN only. Submission secret scan
FAIL causes nonzero exit.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import csv
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingTCPServer
from typing import Any, Literal

Status = Literal["PASS", "WARN", "FAIL"]

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

REQUIRED_PACKAGES = ("pydantic", "yaml", "jsonschema", "boto3")
FIXTURE_SCENARIOS = (
    "scenario_public_admin_vuln_event",
    "scenario_20x_readiness",
    "scenario_agentic_risk",
)
CORE_JSON_FILES = (
    "eval_results.json",
    "evidence_graph.json",
    "correlations.json",
    "assessment_summary.json",
)
ASSESSOR_GAP_COLUMNS = {
    "current_state",
    "target_state",
    "priority",
    "estimated_effort",
    "remediation_steps",
}
SECRET_REGEXES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,}"),
    re.compile(r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"sk-ant-api[a-zA-Z0-9_-]{20,}"),
    re.compile(r"sk-proj-[a-zA-Z0-9_-]{20,}"),
)


@dataclass
class Row:
    status: Status
    section: str
    name: str
    detail: str = ""


def _add(rows: list[Row], status: Status, section: str, name: str, detail: str = "") -> None:
    rows.append(Row(status, section, name, detail))


def _run_agent(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str]:
    cmd = [sys.executable, str(cwd / "agent.py"), *args]
    r = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env or os.environ.copy(),
        timeout=600,
    )
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out[-8000:] if len(out) > 8000 else out


def _check_imports(rows: list[Row]) -> None:
    for mod in REQUIRED_PACKAGES:
        try:
            if mod == "yaml":
                __import__("yaml")
            else:
                __import__(mod)
            _add(rows, "PASS", "environment", f"import {mod}")
        except ImportError as e:
            _add(rows, "FAIL", "environment", f"import {mod}", str(e))


def _check_output_writable(rows: list[Row], out_dir: Path) -> None:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        p = out_dir / ".buildlab_write_probe"
        p.write_text("ok", encoding="utf-8")
        p.unlink(missing_ok=True)
        _add(rows, "PASS", "environment", "output/ writable", str(out_dir))
    except OSError as e:
        _add(rows, "FAIL", "environment", "output/ writable", str(e))


def _check_http_serve(rows: list[Row], root: Path) -> None:
    class H(SimpleHTTPRequestHandler):
        def __init__(self, *a: Any, **kw: Any) -> None:
            super().__init__(*a, directory=str(root), **kw)

        def log_message(self, fmt: str, *log_args: object) -> None:
            pass

    try:
        with ThreadingTCPServer(("127.0.0.1", 0), H) as httpd:
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            try:
                url = f"http://127.0.0.1:{port}/web/sample-data/eval_results.json"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read()
                json.loads(body)
                _add(rows, "PASS", "environment", "HTTP serves web/sample-data", url)
            finally:
                httpd.shutdown()
                t.join(timeout=2)
    except Exception as e:
        _add(rows, "FAIL", "environment", "HTTP serves web/sample-data", str(e))


def _optional_api_keys(rows: list[Row]) -> None:
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        _add(rows, "PASS", "environment", "optional LLM API key", "OPENAI_API_KEY or ANTHROPIC_API_KEY set")
    else:
        _add(
            rows,
            "WARN",
            "environment",
            "optional LLM API key",
            "No OPENAI_API_KEY / ANTHROPIC_API_KEY — grounded UI fallback still works offline.",
        )


def _optional_fastapi(rows: list[Row]) -> None:
    try:
        __import__("fastapi")
        _add(rows, "PASS", "environment", "optional FastAPI (explain API)", "fastapi import OK")
    except ImportError:
        _add(
            rows,
            "WARN",
            "environment",
            "optional FastAPI (explain API)",
            "Install with: pip install -e '.[api]' to run api/server.py on port 8081.",
        )


def _check_python_version(rows: list[Row]) -> None:
    v = sys.version_info
    if v.major >= 3 and v.minor >= 11:
        _add(rows, "PASS", "environment", "Python version", f"{v.major}.{v.minor}.{v.micro}")
    else:
        _add(rows, "FAIL", "environment", "Python version", f"Need >=3.11 (requires-python); got {v.major}.{v.minor}")


def _fixture_demos(rows: list[Row], root: Path, work: Path) -> bool:
    ok = True
    for scenario in FIXTURE_SCENARIOS:
        od = work / f"assess_{scenario}"
        if od.exists():
            shutil.rmtree(od)
        code, tail = _run_agent(
            ["assess", "--provider", "fixture", "--scenario", scenario, "--output-dir", str(od)],
            root,
        )
        if code != 0:
            ok = False
            _add(rows, "FAIL", "fixture", f"assess {scenario}", f"exit {code}\n{tail}")
            continue
        from core.output_validation import validate_evidence_package

        # scenario_20x_readiness is a green/readiness path: all PASS and no generated
        # POA&M rows are intentional, so validate it with the same mode used for
        # arbitrary live environments.
        mode = "live" if scenario == "scenario_20x_readiness" else "demo"
        errs = validate_evidence_package(od, mode=mode)
        if errs:
            ok = False
            _add(rows, "FAIL", "fixture", f"validate package {scenario}", "\n".join(errs[:12]))
        else:
            _add(rows, "PASS", "fixture", f"assess + validate {scenario}", str(od))
    return ok


def _package_readiness(rows: list[Row], root: Path) -> bool:
    pkg_dir = root / "evidence" / "package"
    pkg_json = pkg_dir / "fedramp20x-package.json"
    out_dir = root / "output"
    ok = True

    for name in ("eval_results.json", "evidence_graph.json"):
        p = out_dir / name
        if p.is_file():
            try:
                json.loads(p.read_text(encoding="utf-8"))
                _add(rows, "PASS", "package", f"output/{name}", "valid JSON")
            except Exception as e:
                ok = False
                _add(rows, "FAIL", "package", f"output/{name}", str(e))
        else:
            ok = False
            _add(rows, "FAIL", "package", f"output/{name}", "missing")

    if not pkg_json.is_file():
        ok = False
        _add(rows, "FAIL", "package", "evidence/package/fedramp20x-package.json", "missing")
    else:
        _add(rows, "PASS", "package", "evidence/package/fedramp20x-package.json", "present")

    schemas = root / "schemas"
    if pkg_json.is_file():
        code, tail = _run_agent(
            ["validate-20x-package", "--package", str(pkg_json), "--schemas", str(schemas)],
            root,
        )
        if code != 0:
            ok = False
            _add(rows, "FAIL", "package", "schema validate fedramp20x-package.json", tail.strip()[-2000:])
        else:
            _add(rows, "PASS", "package", "schema validate fedramp20x-package.json", "FEDRAMP 20X PACKAGE SCHEMA: OK")

    rep_md = pkg_dir / "reports" / "executive" / "executive-summary.md"
    if rep_md.is_file():
        _add(rows, "PASS", "package", "reports generated", str(rep_md.relative_to(root)))
    else:
        ok = False
        _add(rows, "FAIL", "package", "reports generated", f"missing {rep_md}")

    code, tail = _run_agent(["reconcile-reports", "--package-output", str(pkg_dir)], root)
    if code != 0:
        ok = False
        _add(rows, "FAIL", "package", "reconciliation", tail.strip()[-2000:])
    else:
        _add(rows, "PASS", "package", "reconciliation", "RECONCILIATION: PASS")

    return ok


def _web_readiness(rows: list[Row], root: Path) -> bool:
    sd = root / "web" / "sample-data"
    ok = True
    if not sd.is_dir():
        _add(rows, "FAIL", "web", "web/sample-data", "directory missing")
        return False

    for name in CORE_JSON_FILES:
        p = sd / name
        if not p.is_file():
            ok = False
            _add(rows, "FAIL", "web", f"sample-data/{name}", "missing")
            continue
        try:
            json.loads(p.read_text(encoding="utf-8"))
            _add(rows, "PASS", "web", f"load {name}", "JSON parse OK")
        except Exception as e:
            ok = False
            _add(rows, "FAIL", "web", f"load {name}", str(e))

    try:
        from api.explain import build_grounded_user_message

        ev_path = sd / "eval_results.json"
        data = json.loads(ev_path.read_text(encoding="utf-8"))
        first = (data.get("evaluations") or data.get("results") or [{}])[0]
        if not isinstance(first, dict):
            first = {}
        msg = build_grounded_user_message(
            mode="explain",
            question="Summarize this evaluation.",
            audience="assessor",
            selected_eval=first if first else None,
            related_evidence=None,
            related_graph=None,
            related_poam=None,
            fedramp20x_context=None,
        )
        if "Task mode:" in msg and "Structured inputs" in msg:
            _add(rows, "PASS", "web", "AI fallback grounded prompt", "build_grounded_user_message OK")
        else:
            ok = False
            _add(rows, "FAIL", "web", "AI fallback grounded prompt", "unexpected message shape")
    except Exception as e:
        ok = False
        _add(rows, "FAIL", "web", "AI fallback grounded prompt", str(e))

    if not (root / "scripts" / "serve_web.py").is_file():
        ok = False
        _add(rows, "FAIL", "web", "scripts/serve_web.py", "missing")
    else:
        _add(rows, "PASS", "web", "scripts/serve_web.py", "present (python scripts/serve_web.py)")

    ar = sd / "agent_run_trace.json"
    if not ar.is_file():
        ok = False
        _add(rows, "FAIL", "web", "sample-data/agent_run_trace.json", "missing (Explorer agent run panel)")
    else:
        try:
            tr = json.loads(ar.read_text(encoding="utf-8"))
            if not tr.get("bounded_playbook"):
                ok = False
                _add(rows, "FAIL", "web", "agent_run_trace bounded_playbook", "expected true")
            else:
                _add(rows, "PASS", "web", "sample-data/agent_run_trace.json", "bounded autonomy trace present")
        except Exception as e:
            ok = False
            _add(rows, "FAIL", "web", "sample-data/agent_run_trace.json", str(e))

    ars = sd / "agent_run_summary.md"
    if not ars.is_file():
        ok = False
        _add(rows, "FAIL", "web", "sample-data/agent_run_summary.md", "missing")
    else:
        _add(rows, "PASS", "web", "sample-data/agent_run_summary.md", "present")

    gap = sd / "evidence_gap_matrix.csv"
    if not gap.is_file():
        ok = False
        _add(rows, "FAIL", "web", "sample-data/evidence_gap_matrix.csv", "missing")
    else:
        try:
            with gap.open("r", encoding="utf-8-sig", newline="") as f:
                gap_rows = list(csv.DictReader(f))
            headers = set(gap_rows[0].keys()) if gap_rows else set()
            missing = sorted(ASSESSOR_GAP_COLUMNS - headers)
            actionable = [
                r
                for r in gap_rows
                if r.get("result") in {"FAIL", "PARTIAL"}
                and r.get("current_state")
                and r.get("target_state")
                and r.get("remediation_steps")
            ]
            if missing:
                ok = False
                _add(rows, "FAIL", "web", "sample-data/evidence_gap_matrix.csv", "missing columns: " + ", ".join(missing))
            elif not actionable:
                ok = False
                _add(
                    rows,
                    "FAIL",
                    "web",
                    "sample-data assessor workpapers",
                    "expected at least one FAIL/PARTIAL row with current, target, and remediation",
                )
            else:
                _add(
                    rows,
                    "PASS",
                    "web",
                    "sample-data assessor workpapers",
                    f"{len(actionable)} actionable matrix row(s)",
                )
        except Exception as e:
            ok = False
            _add(rows, "FAIL", "web", "sample-data/evidence_gap_matrix.csv", str(e))

    app_js = root / "web" / "app.js"
    if not app_js.is_file():
        ok = False
        _add(rows, "FAIL", "web", "web/app.js", "missing")
    else:
        text = app_js.read_text(encoding="utf-8", errors="replace")
        required = (
            'if (name === "evidence_gap_matrix.csv")',
            "state.gapMatrix = rows",
            "matrixRowsForEval",
            "Assessor workpaper",
            "renderCapabilities",
            "renderReasonableTest",
            "renderLiveCoverage",
            "renderConmonWorkbench",
        )
        missing = [needle for needle in required if needle not in text]
        if missing:
            ok = False
            _add(rows, "FAIL", "web", "Explorer assessor UI contract", "missing: " + ", ".join(missing))
        else:
            _add(rows, "PASS", "web", "Explorer assessor UI contract", "gap matrix renders as assessor context")

    html = root / "web" / "index.html"
    if html.is_file():
        htext = html.read_text(encoding="utf-8", errors="replace")
        workbench_labels = (
            "Capabilities &amp; References",
            "3PAO Reasonable Test",
            "Live Collection Coverage",
            "ConMon Workbench",
            "Public Exposure",
            "Package Diff",
            "AI Backend Status",
        )
        missing = [label for label in workbench_labels if label not in htext]
        if missing:
            ok = False
            _add(rows, "FAIL", "web", "Assessment workbench panels", "missing: " + ", ".join(missing))
        else:
            _add(rows, "PASS", "web", "Assessment workbench panels", "reference, reasonableness, live, ConMon, exposure, diff, AI status")

    return ok


def _cloud_readiness(rows: list[Row]) -> None:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        _add(rows, "WARN", "cloud", "AWS STS", "boto3 unavailable (should not happen)")
        return

    try:
        ident = boto3.client("sts").get_caller_identity()
        aid = ident.get("Account", "")
        arn = ident.get("Arn", "")
        _add(rows, "PASS", "cloud", "sts get-caller-identity", f"account={aid} arn={arn}")
    except (NoCredentialsError, BotoCoreError, ClientError) as e:
        _add(
            rows,
            "WARN",
            "cloud",
            "sts get-caller-identity",
            f"Live cloud mode unavailable (no usable credentials): {e}",
        )


def _scan_secrets_in_output(rows: list[Row], out_dir: Path) -> bool:
    hits: list[str] = []
    if not out_dir.is_dir():
        _add(rows, "WARN", "submission", "secrets scan output/", "output/ missing — skipped")
        return True
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".json", ".md", ".csv", ".txt", ".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rx in SECRET_REGEXES:
            if rx.search(text):
                hits.append(f"{path.relative_to(out_dir)}: matched {rx.pattern[:40]}...")
                break
    if hits:
        _add(rows, "FAIL", "submission", "no secrets in output/", "; ".join(hits[:8]))
        return False
    _add(rows, "PASS", "submission", "no secrets in output/", "no high-confidence patterns in text artifacts")
    return True


def _guard_curated_live_artifacts(rows: list[Row], root: Path) -> bool:
    try:
        from scripts.guard_live_artifacts import DEFAULT_ALLOWED_ACCOUNTS, DEFAULT_PATHS, scan_paths
    except Exception as e:
        _add(rows, "FAIL", "submission", "live artifact guard import", str(e))
        return False

    findings = scan_paths(
        [p.resolve() for p in DEFAULT_PATHS],
        allowed_accounts=set(DEFAULT_ALLOWED_ACCOUNTS),
        base=root,
    )
    if findings:
        detail = "; ".join(f"{f.file}:{f.line}" for f in findings[:8])
        _add(rows, "FAIL", "submission", "no live AWS ids in curated artifacts", detail)
        return False
    _add(
        rows,
        "PASS",
        "submission",
        "no live AWS ids in curated artifacts",
        "sample-data, evidence packages, reports, and validation_run are clean",
    )
    return True


def _submission_docs(rows: list[Row], root: Path) -> bool:
    ok = True
    readme = root / "README.md"
    if readme.is_file():
        _add(rows, "PASS", "submission", "README.md", "present")
    else:
        ok = False
        _add(rows, "FAIL", "submission", "README.md", "missing")

    walk = root / "output" / "demo_walkthrough.md"
    walk_cf = root / "output" / "demo_walkthrough_coalfire.md"
    if walk.is_file() or walk_cf.is_file():
        _add(
            rows,
            "PASS",
            "submission",
            "demo walkthrough",
            str(walk) if walk.is_file() else str(walk_cf),
        )
    else:
        ok = False
        _add(rows, "FAIL", "submission", "demo walkthrough", "missing output/demo_walkthrough.md (and coalfire variant)")

    just = root / "docs" / "why_this_is_not_reinventing_the_wheel.md"
    if just.is_file():
        _add(rows, "PASS", "submission", "reference justification", str(just.relative_to(root)))
    else:
        ok = False
        _add(rows, "FAIL", "submission", "reference justification", "missing docs/why_this_is_not_reinventing_the_wheel.md")

    return ok


def _conmon_reasonableness_readiness(rows: list[Row], root: Path) -> bool:
    catalog = root / "config" / "conmon-catalog.yaml"
    tracker = root / "fixtures" / "assessment_tracker" / "conmon_19_tracker.csv"
    out_dir = root / "output" / "conmon_reasonableness"
    code, tail = _run_agent(
        [
            "conmon-reasonableness",
            "--catalog",
            str(catalog),
            "--tracker",
            str(tracker),
            "--output-dir",
            str(out_dir),
        ],
        root,
    )
    if code != 0:
        _add(rows, "FAIL", "submission", "ConMon reasonableness", tail.strip()[-2000:])
        return False
    report = out_dir / "conmon_reasonableness.md"
    payload = out_dir / "conmon_reasonableness.json"
    if not report.is_file() or not payload.is_file():
        _add(rows, "FAIL", "submission", "ConMon reasonableness outputs", "missing markdown or JSON output")
        return False
    try:
        data = json.loads(payload.read_text(encoding="utf-8"))
        summary = data.get("summary") or {}
        ecosystems = data.get("evidence_ecosystems") or {}
        text = report.read_text(encoding="utf-8")
        required_text = ("AWS CloudTrail", "Splunk", "Wazuh", "Smartsheet", "Jira", "ServiceNow", "3PAO")
        if int(summary.get("obligations") or 0) < 15 or not all(s in text for s in required_text):
            _add(rows, "FAIL", "submission", "ConMon reasonableness coverage", "catalog/report missing required 3PAO evidence-system coverage")
            return False
        if "ticketing" not in ecosystems or "aws" not in ecosystems or "siem" not in ecosystems:
            _add(rows, "FAIL", "submission", "ConMon reasonableness ecosystems", "missing aws/siem/ticketing ecosystem metadata")
            return False
        from ai import explain_conmon_reasonableness, llm_backend_status

        ai_out = explain_conmon_reasonableness(conmon_result=data)
        status = llm_backend_status(reasoners=["explain_conmon_reasonableness"])
        if ai_out.referenced_eval_id != "CONMON_REASONABLENESS" or not ai_out.citations:
            _add(rows, "FAIL", "submission", "ConMon AI reasoner", "missing typed reasoner citation/eval reference")
            return False
        if "explain_conmon_reasonableness" not in (status.get("reasoners") or []):
            _add(rows, "FAIL", "submission", "ConMon AI backend status", "reasoner not advertised")
            return False
    except Exception as e:
        _add(rows, "FAIL", "submission", "ConMon reasonableness parse", str(e))
        return False
    _add(
        rows,
        "PASS",
        "submission",
        "ConMon reasonableness",
        f"{summary.get('obligations')} obligations; 3PAO ecosystem report + AI reasoner present",
    )
    return True


def _zip_safe_artifact_list(root: Path) -> list[str]:
    """Paths intended for a reviewer zip (no secrets, no venv)."""
    rels: list[str] = [
        "README.md",
        "pyproject.toml",
        "agent.py",
        "config/",
        "core/",
        "providers/",
        "evals/",
        "fedramp20x/",
        "fixtures/",
        "schemas/",
        "web/",
        "scripts/",
        "tests/",
        "docs/",
        "output/demo_walkthrough.md",
        "output/demo_walkthrough_coalfire.md",
        "evidence/package/",
        "instrumentation/",
        "api/",
    ]
    lines = [
        "Suggested zip roots (verify before shipping):",
        "",
        "```",
        *[f"  {r}" for r in rels],
        "```",
        "",
        "Exclude: `.git/`, `venv/`, `.venv/`, `__pycache__/`, `*.pyc`, `creds.json`, `.env`, `.buildlab_readiness/`.",
    ]
    return lines


def _render_md(rows: list[Row], zip_lines: list[str], demo_cmds: list[str], fallback: list[str]) -> str:
    lines = [
        "# BuildLab readiness",
        "",
        "Auto-generated by `python scripts/buildlab_readiness.py`.",
        "",
        "## Checklist",
        "",
        "| Status | Section | Check | Detail |",
        "|--------|---------|-------|--------|",
    ]
    for r in rows:
        d = (r.detail or "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {r.status} | {r.section} | {r.name} | {d} |")
    lines.extend(["", "## Demo commands", ""])
    lines.extend(demo_cmds)
    lines.extend(["", "## Fallback (offline / no Wi‑Fi / no cloud)", ""])
    lines.extend(fallback)
    lines.extend(["", "## Zip-safe artifact list", ""])
    lines.extend(zip_lines)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    root = _ROOT
    out_md = root / "output" / "buildlab_readiness.md"
    rows: list[Row] = []

    _check_python_version(rows)
    _check_imports(rows)
    _check_output_writable(rows, root / "output")
    _check_http_serve(rows, root)
    _optional_api_keys(rows)
    _optional_fastapi(rows)

    with tempfile.TemporaryDirectory(prefix="buildlab_readiness_") as tmp:
        work = Path(tmp)
        fixture_ok = _fixture_demos(rows, root, work)

    package_ok = _package_readiness(rows, root)
    web_ok = _web_readiness(rows, root)
    _cloud_readiness(rows)
    submission_docs_ok = _submission_docs(rows, root)
    conmon_ok = _conmon_reasonableness_readiness(rows, root)
    secrets_ok = _scan_secrets_in_output(rows, root / "output")
    live_artifacts_ok = _guard_curated_live_artifacts(rows, root)

    zip_lines = _zip_safe_artifact_list(root)
    _add(rows, "PASS", "submission", "zip-safe artifact list", "see section below")

    demo_cmds = [
        "```bash",
        "cd observable-security-agent  # repo root containing agent.py",
        "",
        "# Fixture assessment (pick one scenario)",
        "python agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir output",
        "python agent.py assess --provider fixture --scenario scenario_20x_readiness --output-dir output",
        "python agent.py assess --provider fixture --scenario scenario_agentic_risk --output-dir output",
        "",
        "# Validate assessment output",
        "python agent.py validate --output-dir output",
        "",
        "# 20x package from a fresh assess output dir",
        "python agent.py build-20x-package --assessment-output output --config config --package-output evidence/package",
        "python agent.py validate-20x-package --package evidence/package/fedramp20x-package.json --schemas schemas",
        "python agent.py reconcile-reports --package-output evidence/package",
        "",
        "# Bounded autonomous loop (fixture; writes trace + agentic assess under output_agentic/ by default)",
        "python agent.py run-agent --provider fixture --scenario scenario_agentic_risk",
        "",
        "# ConMon / 3PAO reasonableness over Smartsheet/Jira/ServiceNow-style exports",
        "python agent.py conmon-reasonableness --tracker fixtures/assessment_tracker/conmon_19_tracker.csv --output-dir output/conmon_reasonableness",
        "# Optional LLM backends use OpenAI-compatible transport:",
        "#   LiteLLM/Bedrock: AI_API_BASE=http://127.0.0.1:4000/v1 AI_MODEL=bedrock/... AI_API_KEY=...",
        "#   Ollama:          AI_BACKEND=ollama AI_API_BASE=http://127.0.0.1:11434/v1 AI_MODEL=llama3.1",
        "",
        "# Static web (serves repo root; Explorer loads ../output/ or web/sample-data/)",
        "python scripts/serve_web.py",
        "# Open http://127.0.0.1:8080/web/index.html",
        "",
        "# Optional grounded explain API (requires pip install -e '.[api]')",
        "uvicorn api.server:app --host 127.0.0.1 --port 8081",
        "```",
    ]
    fallback = [
        "- **No Wi‑Fi / blocked ports:** rely on `web/sample-data/*.json`; open `web/index.html` via `file://` only if",
        "  your browser allows `fetch` from file URLs; otherwise use `python scripts/serve_web.py` on localhost.",
        "- **No cloud credentials:** fixture and package checks do not require AWS; live STS is optional (WARN only).",
        "- **No LLM API key:** the Explorer uses `api.explain` grounded prompts; optional `uvicorn` explain server",
        "  falls back to deterministic text when the model is unreachable.",
    ]

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_render_md(rows, zip_lines, demo_cmds, fallback), encoding="utf-8")

    fail_sections = {"environment", "fixture", "package", "web", "submission"}
    any_fail = any(r.status == "FAIL" and r.section in fail_sections for r in rows)
    warn_n = sum(1 for r in rows if r.status == "WARN")
    pass_n = sum(1 for r in rows if r.status == "PASS")
    fail_n = sum(1 for r in rows if r.status == "FAIL")
    print(f"Wrote {out_md}")
    print(f"Summary: PASS={pass_n} WARN={warn_n} FAIL={fail_n}")
    if any_fail:
        print("Readiness: FAIL (see output/buildlab_readiness.md)")
        return 1
    print("Readiness: OK (fixture + package + web gates passed; cloud issues are WARN-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
