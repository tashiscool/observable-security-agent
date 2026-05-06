#!/usr/bin/env python3
"""One-shot end-to-end validation of the Observable Security Agent.

Runs **reference-backed gates first** (inventory, manifest, reuse audit,
adapter/regression tests scoped to ``reference_samples/``, policy + graph
vocabulary, 20x package unit tests, required docs), then the full assessment /
tracker / reconciliation / web / AI pipelines, and finally secret scanning.

Usage::

    python scripts/validate_everything.py \\
        --tracker fixtures/assessment_tracker/sample_tracker.csv \\
        --output-root validation_run

Outputs::

    validation_run/validation_summary.json     - structured per-step result grid
    validation_run/validation_summary.md     - full run rollup + demo links
    validation_run/reference_validation_summary.md - reference-only subset + rules
    validation_run/reference_reuse_audit.md  - written by ``audit_reference_reuse.py``
    validation_run/commands.log                - every shell command + rc + dur
    validation_run/failures.log              - each FAIL with stderr / detail

Reference validation rules
--------------------------

* Missing **optional** ``reference_samples`` file (adapter JSON/CSV) → **WARN**
  only — see ``reference_samples/README.md`` (controlled sample area).
* **Broken adapter when the sample is present** → **FAIL** (pytest).
* **Runtime import** from ``reference_samples`` or ``reference.*`` → **FAIL**
  (``scripts/audit_reference_reuse.py``).
* **Missing license** manifest parity / on-disk license files → **FAIL**
  (same audit script).

Status semantics
----------------

* **PASS** - the step's hard contract held.
* **WARN** - optional inputs missing, credentials unset but fallback OK, etc.
* **FAIL** - pytest non-zero, schema/narrative/reuse/hallucination violations,
  or secret-shaped values in generated artifacts (non-allowlisted).
* **SKIP** - prerequisite step failed.

Exit code is ``0`` when every step is PASS / WARN / SKIP, ``1`` otherwise.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"
TERMINAL_STATUSES = {PASS, WARN, FAIL, SKIP}


@dataclass
class StepResult:
    """One row in the validation grid."""

    step_id: str
    title: str
    status: str = SKIP
    summary: str = ""
    details: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Context:
    """Shared writable state for all steps."""

    tracker_csv: Path
    output_root: Path
    repo_root: Path
    config_dir: Path
    schemas_dir: Path
    started_at: _dt.datetime
    cmd_log: Path
    fail_log: Path
    skip_pytest: bool = False
    fast_pytest: bool = False
    keep_root: bool = False

    @property
    def assessment_dirs(self) -> dict[str, Path]:
        return {
            "fixture": self.output_root / "fixture_assessment",
            "agentic": self.output_root / "agentic_assessment",
            "readiness": self.output_root / "readiness_assessment",
        }

    @property
    def tracker_dirs(self) -> dict[str, Path]:
        return {
            "import_only": self.output_root / "scenario_from_tracker_import",
            "classify_only": self.output_root / "scenario_from_tracker_classify",
            "tracker_to_20x": self.output_root / "tracker_to_20x",
            "agent_run": self.output_root / "agent_run_tracker",
        }


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)
        if not line.endswith("\n"):
            fh.write("\n")


def _shorten(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    return f"{head}\n...[truncated {len(text) - limit} chars]...\n{tail}"


def run_command(
    ctx: Context,
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess, append to commands.log, and return the CompletedProcess.

    The full stdout/stderr is captured and appended to the log; the caller
    receives the same CompletedProcess so it can decide what to do.
    """
    started = time.time()
    pretty = " ".join(_shellquote(c) for c in cmd)
    work_dir = cwd or ctx.repo_root
    proc = subprocess.run(
        list(cmd),
        cwd=str(work_dir),
        env={**os.environ, **(env or {})},
        capture_output=capture,
        text=True,
        timeout=timeout,
        check=False,
    )
    dur_ms = int((time.time() - started) * 1000)
    summary = (
        f"[{_now_iso()}] (rc={proc.returncode}, dur={dur_ms}ms) {pretty}\n"
        f"  cwd: {work_dir}\n"
    )
    if proc.stdout:
        summary += "  --- stdout ---\n" + _indent(_shorten(proc.stdout, 2000)) + "\n"
    if proc.stderr:
        summary += "  --- stderr ---\n" + _indent(_shorten(proc.stderr, 2000)) + "\n"
    _append(ctx.cmd_log, summary)
    return proc


def _shellquote(s: str) -> str:
    if not s or any(ch in s for ch in " \t'\"$&|<>;()*?"):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.rstrip("\n").splitlines())


def record_failure(ctx: Context, step: StepResult) -> None:
    block = (
        f"[{_now_iso()}] FAIL {step.step_id} :: {step.title}\n"
        f"  summary: {step.summary}\n"
    )
    if step.details:
        block += "  details:\n" + _indent("\n".join(step.details)) + "\n"
    if step.commands:
        block += "  commands:\n" + _indent("\n".join(step.commands)) + "\n"
    _append(ctx.fail_log, block)


# ---------------------------------------------------------------------------
# Step framework
# ---------------------------------------------------------------------------

PRECONDITIONS: dict[str, set[str]] = {
    # step_id -> set of upstream step_ids that must NOT have FAIL'd.
    "20x_readiness_assessment": {"fixture_cloud_assessment"},
    "tracker_gap_classification": {"tracker_import"},
    "tracker_to_20x_package": {"tracker_import"},
    "agent_loop_tracker_to_20x": {"tracker_import"},
    "package_schema_validation": {
        "20x_readiness_assessment",
        "tracker_to_20x_package",
        "agent_loop_tracker_to_20x",
    },
    "narrative_validation": {
        "fixture_cloud_assessment",
        "tracker_to_20x_package",
        "agent_loop_tracker_to_20x",
    },
    "reconciliation_validation": {
        "20x_readiness_assessment",
        "tracker_to_20x_package",
        "agent_loop_tracker_to_20x",
    },
    "web_sample_data_preparation": {"agent_loop_tracker_to_20x"},
    "secret_scan_generated_outputs": set(),  # always runs
}


# Regex for tests + tools matching runtime imports from reference trees.
_RUNTIME_PYTHON_DIRS = (
    "agent.py",
    "agent_loop",
    "ai",
    "api",
    "classification",
    "core",
    "evals",
    "fedramp20x",
    "normalization",
    "providers",
    "scripts",
)


def _python_files(repo_root: Path) -> list[Path]:
    out: list[Path] = []
    for entry in _RUNTIME_PYTHON_DIRS:
        target = repo_root / entry
        if target.is_file() and target.suffix == ".py":
            out.append(target)
        elif target.is_dir():
            for p in target.rglob("*.py"):
                if "/__pycache__/" in str(p):
                    continue
                out.append(p)
    return out


_REF_IMPORT_RE = re.compile(
    r"^\s*("
    r"from\s+reference_samples(?:\.[A-Za-z_][\w]*)*\s+import\s+"
    r"|import\s+reference_samples(?:\.[A-Za-z_][\w]*)*"
    r"|from\s+reference(?:\.[A-Za-z_][\w]*)*\s+import\s+"
    r"|import\s+reference(?:\.[A-Za-z_][\w]*)+"
    r")",
    re.MULTILINE,
)


def _start_step(step_id: str, title: str) -> StepResult:
    return StepResult(step_id=step_id, title=title, started_at=_now_iso())


def _finish_step(
    step: StepResult,
    *,
    started_perf: float,
    status: str,
    summary: str,
    details: Iterable[str] | None = None,
    artifacts: Iterable[Path] | None = None,
    commands: Iterable[str] | None = None,
) -> StepResult:
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"unknown status {status!r}")
    step.status = status
    step.summary = summary
    if details:
        step.details = list(details)
    if artifacts:
        step.artifacts = [str(p) for p in artifacts]
    if commands:
        step.commands = list(commands)
    step.completed_at = _now_iso()
    step.duration_ms = int((time.time() - started_perf) * 1000)
    return step


def _skip_if_prereqs_failed(
    step_id: str, results: dict[str, StepResult]
) -> StepResult | None:
    """Return a SKIP StepResult if any prerequisite has status FAIL."""
    failed_prereqs = [
        sid for sid in PRECONDITIONS.get(step_id, set()) if (results.get(sid) and results[sid].status == FAIL)
    ]
    if not failed_prereqs:
        return None
    skip = _start_step(step_id, _step_titles()[step_id])
    return _finish_step(
        skip,
        started_perf=time.time(),
        status=SKIP,
        summary=f"prerequisite step(s) FAILED: {', '.join(failed_prereqs)}",
    )


# ---------------------------------------------------------------------------
# Step registry
# ---------------------------------------------------------------------------


def _step_titles() -> dict[str, str]:
    return {
        "unit_tests": "1. Unit tests (pytest -q)",
        "reference_repo_inventory": "2. Reference repo inventory (docs/reference_repo_inventory.md)",
        "reference_samples_manifest_validate": "3. reference_samples manifest validates (structure + on-disk parity)",
        "reference_reuse_audit": "4. Reference reuse audit (audit_reference_reuse.py: licenses, imports, duplicates)",
        "adapter_prowler_reference_sample": "5. Prowler adapter tests (if reference sample present)",
        "adapter_cloudsploit_reference_sample": "6. CloudSploit adapter tests (if reference sample present)",
        "adapter_ocsf_reference_sample": "7. OCSF adapter tests (if reference sample present)",
        "public_exposure_policy_validation": "8. Public exposure policy validates (pytest)",
        "evidence_graph_vocabulary_validation": "9. Evidence graph relationship vocabulary (pytest)",
        "fedramp20x_reference_package_validation": "10. FedRAMP 20x package unit tests (pytest)",
        "reference_gap_matrix_document": "11. reference_gap_matrix.md exists",
        "reference_traceability_document": "12. reference_to_implementation_traceability.md exists",
        "fixture_cloud_assessment": "13. Fixture cloud assessment (scenario_public_admin_vuln_event)",
        "agentic_risk_assessment": "14. Agentic risk assessment (scenario_agentic_risk + agent security)",
        "20x_readiness_assessment": "15. 20x readiness assessment + build package",
        "tracker_import": "16. Tracker import",
        "tracker_gap_classification": "17. Tracker gap classification",
        "tracker_to_20x_package": "18. Tracker -> 20x package",
        "agent_loop_tracker_to_20x": "19. Agent loop tracker-to-20x",
        "package_schema_validation": "20. Package schema validation (validate-20x-package)",
        "narrative_validation": "21. Narrative validation + validate_outputs (fixture)",
        "reconciliation_validation": "22. Reconciliation validation",
        "web_sample_data_preparation": "23. Web sample-data preparation",
        "ai_fallback_explanation_test": "24. AI fallback explanation test",
        "secret_scan_generated_outputs": "25. Secret scan of generated outputs",
    }


_REFERENCE_VALIDATION_SUMMARY_STEP_IDS: frozenset[str] = frozenset(
    {
        "reference_repo_inventory",
        "reference_samples_manifest_validate",
        "reference_reuse_audit",
        "adapter_prowler_reference_sample",
        "adapter_cloudsploit_reference_sample",
        "adapter_ocsf_reference_sample",
        "public_exposure_policy_validation",
        "evidence_graph_vocabulary_validation",
        "fedramp20x_reference_package_validation",
        "reference_gap_matrix_document",
        "reference_traceability_document",
    }
)

_OPTIONAL_REFERENCE_SAMPLE_README = "reference_samples/README.md"


def _run_pytest_subset(
    ctx: Context,
    *,
    step_id: str,
    pytest_paths: list[str],
    timeout: int = 600,
) -> StepResult:
    step = _start_step(step_id, _step_titles()[step_id])
    started = time.time()
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", *pytest_paths]
    proc = run_command(ctx, cmd, timeout=timeout)
    cmd_str = " ".join(_shellquote(c) for c in cmd)
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"pytest exited {proc.returncode}",
            details=[_shorten((proc.stdout or "") + (proc.stderr or ""), 2500)],
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"pytest OK: {', '.join(pytest_paths)}",
        commands=[cmd_str],
    )


def step_reference_repo_inventory(ctx: Context) -> StepResult:
    step = _start_step("reference_repo_inventory", _step_titles()["reference_repo_inventory"])
    started = time.time()
    doc = ctx.repo_root / "docs" / "reference_repo_inventory.md"
    if not doc.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="missing docs/reference_repo_inventory.md",
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"found {_safe_rel(doc, ctx.repo_root)}",
        artifacts=[doc],
    )


def step_reference_samples_manifest_validate(ctx: Context) -> StepResult:
    """Parse manifest, required keys, reciprocal on-disk parity, license dir consistency."""
    step = _start_step(
        "reference_samples_manifest_validate",
        _step_titles()["reference_samples_manifest_validate"],
    )
    started = time.time()
    rs = ctx.repo_root / "reference_samples"
    man = rs / "manifest.json"
    if not man.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="missing reference_samples/manifest.json",
        )
    try:
        data = json.loads(man.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"manifest JSON invalid: {e}",
        )
    entries = data.get("files")
    if not isinstance(entries, list) or not entries:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="manifest `files` must be a non-empty array",
        )
    required_keys = ("source_project", "original_path", "copied_path", "reason_copied", "category")
    bad_entries: list[str] = []
    manifest_paths: set[str] = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            bad_entries.append(f"files[{i}] is not an object")
            continue
        cp = str(e.get("copied_path") or "").replace("\\", "/")
        if not cp.strip():
            bad_entries.append(f"files[{i}] missing copied_path")
            continue
        manifest_paths.add(cp)
        for k in required_keys:
            val = e.get(k)
            if not isinstance(val, str) or not val.strip():
                bad_entries.append(f"files[{i}] invalid or empty {k!r}")
        p = ctx.repo_root / cp
        if not p.is_file():
            bad_entries.append(f"missing on disk: {cp}")
    on_disk: set[str] = set()
    if rs.is_dir():
        on_disk = {
            str(p.relative_to(ctx.repo_root)).replace("\\", "/")
            for p in rs.rglob("*")
            if p.is_file() and p.name not in ("README.md", "manifest.json")
        }
    extra = sorted(on_disk - manifest_paths)
    missing_from_disk = sorted(manifest_paths - on_disk)
    lic_dir = rs / "licenses"
    lic_issues: list[str] = []
    if lic_dir.is_dir():
        lic_files = {
            str(p.relative_to(ctx.repo_root)).replace("\\", "/")
            for p in lic_dir.iterdir()
            if p.is_file()
        }
        for lf in sorted(lic_files - manifest_paths):
            lic_issues.append(f"license file on disk not in manifest: {lf}")
        for mp in sorted(manifest_paths):
            if mp.startswith("reference_samples/licenses/") and mp not in on_disk:
                lic_issues.append(f"manifest license path missing on disk: {mp}")
    failures = bad_entries + [f"on-disk file not in manifest: {x}" for x in extra]
    failures += [f"manifest lists missing file: {x}" for x in missing_from_disk]
    failures += lic_issues
    if failures:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"{len(failures)} manifest/LICENSE parity issue(s)",
            details=failures[:40],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"{len(manifest_paths)} manifest entries; licenses dir consistent",
        artifacts=[man],
    )


def step_reference_reuse_audit(ctx: Context) -> StepResult:
    """Delegate to ``scripts/audit_reference_reuse.py`` (imports, dupes, full parity)."""
    step = _start_step("reference_reuse_audit", _step_titles()["reference_reuse_audit"])
    started = time.time()
    out_md = ctx.output_root / "reference_reuse_audit.md"
    cmd = [
        sys.executable,
        str(ctx.repo_root / "scripts" / "audit_reference_reuse.py"),
        "--repo-root",
        str(ctx.repo_root),
        "--output",
        str(out_md),
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(_shellquote(c) for c in cmd)
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=(
                "audit_reference_reuse.py failed — runtime import from reference/, "
                "license/manifest mismatch, or verbatim source in product trees"
            ),
            details=[_shorten((proc.stdout or "") + (proc.stderr or ""), 3000)],
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary="audit_reference_reuse.py PASS",
        artifacts=[out_md] if out_md.is_file() else None,
        commands=[cmd_str],
    )


def _optional_adapter_pytest(
    ctx: Context,
    *,
    step_id: str,
    sample_relative: str,
    pytest_targets: list[str],
) -> StepResult:
    step = _start_step(step_id, _step_titles()[step_id])
    started = time.time()
    sample = ctx.repo_root / sample_relative.replace("/", os.sep)
    if not sample.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=WARN,
            summary=(
                f"reference sample missing: `{sample_relative}` — WARN only "
                f"(optional checkout; see `{_OPTIONAL_REFERENCE_SAMPLE_README}`)"
            ),
            details=[
                "Skipping adapter pytest; broken adapter is not applicable without the sample.",
            ],
        )
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", *pytest_targets]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(_shellquote(c) for c in cmd)
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"pytest exited {proc.returncode} (sample present — adapter must pass)",
            details=[_shorten((proc.stdout or "") + (proc.stderr or ""), 2500)],
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"pytest OK: {', '.join(pytest_targets)}",
        commands=[cmd_str],
    )


def step_adapter_prowler_reference_sample(ctx: Context) -> StepResult:
    return _optional_adapter_pytest(
        ctx,
        step_id="adapter_prowler_reference_sample",
        sample_relative="reference_samples/prowler/outputs/scan_result_sample.json",
        pytest_targets=["tests/test_prowler_adapter.py"],
    )


def step_adapter_cloudsploit_reference_sample(ctx: Context) -> StepResult:
    return _optional_adapter_pytest(
        ctx,
        step_id="adapter_cloudsploit_reference_sample",
        sample_relative="reference_samples/cloudsploit/outputs/scan_result_sample.json",
        pytest_targets=["tests/test_cloudsploit_adapter.py"],
    )


def step_adapter_ocsf_reference_sample(ctx: Context) -> StepResult:
    return _optional_adapter_pytest(
        ctx,
        step_id="adapter_ocsf_reference_sample",
        sample_relative="reference_samples/ocsf/examples/base_event.json",
        pytest_targets=["tests/test_ocsf_adapter.py"],
    )


def step_public_exposure_policy_validation(ctx: Context) -> StepResult:
    return _run_pytest_subset(
        ctx,
        step_id="public_exposure_policy_validation",
        pytest_paths=["tests/test_public_exposure_policy.py"],
    )


def step_evidence_graph_vocabulary_validation(ctx: Context) -> StepResult:
    step = _start_step(
        "evidence_graph_vocabulary_validation",
        _step_titles()["evidence_graph_vocabulary_validation"],
    )
    started = time.time()
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--no-header",
        "tests/test_evidence_graph.py",
        "tests/test_reference_sample_adapters.py::test_graph_reference_cartography_cypher_rel_traced_to_canonical_rel_constants",
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(_shellquote(c) for c in cmd)
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"pytest exited {proc.returncode}",
            details=[_shorten((proc.stdout or "") + (proc.stderr or ""), 2500)],
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary="evidence graph + Cartography vocabulary traceability OK",
        commands=[cmd_str],
    )


def step_fedramp20x_reference_package_validation(ctx: Context) -> StepResult:
    return _run_pytest_subset(
        ctx,
        step_id="fedramp20x_reference_package_validation",
        pytest_paths=[
            "tests/test_fedramp20x_package.py",
            "tests/test_fedramp20x_top_package.py",
            "tests/test_schema_validator_20x.py",
        ],
    )


def step_reference_gap_matrix_document(ctx: Context) -> StepResult:
    step = _start_step(
        "reference_gap_matrix_document",
        _step_titles()["reference_gap_matrix_document"],
    )
    started = time.time()
    path = ctx.repo_root / "docs" / "reference_gap_matrix.md"
    if not path.is_file() or not path.stat().st_size:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="missing or empty docs/reference_gap_matrix.md",
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"found {_safe_rel(path, ctx.repo_root)}",
        artifacts=[path],
    )


def step_reference_traceability_document(ctx: Context) -> StepResult:
    step = _start_step(
        "reference_traceability_document",
        _step_titles()["reference_traceability_document"],
    )
    started = time.time()
    path = ctx.repo_root / "docs" / "reference_to_implementation_traceability.md"
    if not path.is_file() or not path.stat().st_size:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="missing or empty docs/reference_to_implementation_traceability.md",
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"found {_safe_rel(path, ctx.repo_root)}",
        artifacts=[path],
    )


def step_unit_tests(ctx: Context) -> StepResult:
    step = _start_step("unit_tests", _step_titles()["unit_tests"])
    started = time.time()
    if ctx.skip_pytest:
        return _finish_step(
            step,
            started_perf=started,
            status=WARN,
            summary="pytest skipped via --skip-pytest (use only for fast smoke runs)",
        )
    cmd = [sys.executable, "-m", "pytest", "-q"]
    if ctx.fast_pytest:
        cmd += ["-x", "--no-header", "--ignore=output_agent_run", "--ignore=output_agentic"]
    proc = run_command(ctx, cmd, timeout=900)
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"pytest exited {proc.returncode}",
            details=[_shorten(proc.stdout or "", 2000), _shorten(proc.stderr or "", 1000)],
            commands=[" ".join(cmd)],
        )
    last_line = (proc.stdout or "").strip().splitlines()
    summary = last_line[-1] if last_line else "pytest completed"
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=summary,
        commands=[" ".join(cmd)],
    )


def _run_assess(
    ctx: Context,
    *,
    scenario: str,
    output_dir: Path,
    extra: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "agent.py",
        "assess",
        "--provider",
        "fixture",
        "--scenario",
        scenario,
        "--output-dir",
        str(output_dir),
    ]
    if extra:
        cmd += extra
    return run_command(ctx, cmd)


def step_fixture_cloud_assessment(ctx: Context) -> StepResult:
    step = _start_step("fixture_cloud_assessment", _step_titles()["fixture_cloud_assessment"])
    started = time.time()
    out = ctx.assessment_dirs["fixture"]
    proc = _run_assess(ctx, scenario="scenario_public_admin_vuln_event", output_dir=out)
    cmd_str = f"agent.py assess --provider fixture --scenario scenario_public_admin_vuln_event --output-dir {out}"
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"assess exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    eval_results = out / "eval_results.json"
    if not eval_results.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="eval_results.json was not produced",
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"eval_results.json + correlations.json + poam.csv under {_safe_rel(out, ctx.repo_root)}",
        artifacts=[eval_results, out / "poam.csv", out / "correlations.json", out / "evidence_graph.json"],
        commands=[cmd_str],
    )


def step_agentic_risk_assessment(ctx: Context) -> StepResult:
    step = _start_step("agentic_risk_assessment", _step_titles()["agentic_risk_assessment"])
    started = time.time()
    out = ctx.assessment_dirs["agentic"]
    proc = _run_assess(
        ctx,
        scenario="scenario_agentic_risk",
        output_dir=out,
        extra=["--include-agent-security"],
    )
    cmd_str = (
        f"agent.py assess --provider fixture --scenario scenario_agentic_risk "
        f"--include-agent-security --output-dir {out}"
    )
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"assess exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    expected = [
        out / "eval_results.json",
        out / "agent_eval_results.json",
        out / "agent_risk_report.md",
    ]
    missing = [p for p in expected if not p.is_file()]
    if missing:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"missing agentic artifacts: {', '.join(p.name for p in missing)}",
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"agentic eval bundle written under {_safe_rel(out, ctx.repo_root)}",
        artifacts=expected + [out / "agent_threat_hunt_findings.json"],
        commands=[cmd_str],
    )


def step_20x_readiness_assessment(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("20x_readiness_assessment", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("20x_readiness_assessment", _step_titles()["20x_readiness_assessment"])
    started = time.time()
    out = ctx.assessment_dirs["readiness"]
    pkg_out = ctx.output_root / "package_readiness"
    pkg_out.mkdir(parents=True, exist_ok=True)
    proc1 = _run_assess(ctx, scenario="scenario_20x_readiness", output_dir=out)
    cmd1 = f"agent.py assess --provider fixture --scenario scenario_20x_readiness --output-dir {out}"
    if proc1.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"assess exited {proc1.returncode}",
            details=[_shorten(proc1.stderr, 1500)],
            commands=[cmd1],
        )
    cmd_build = [
        sys.executable, "agent.py", "build-20x-package",
        "--assessment-output", str(out),
        "--config", str(ctx.config_dir),
        "--package-output", str(pkg_out),
    ]
    proc2 = run_command(ctx, cmd_build)
    cmd2_str = " ".join(cmd_build[1:])
    if proc2.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"build-20x-package exited {proc2.returncode}",
            details=[_shorten(proc2.stderr, 1500)],
            commands=[cmd1, cmd2_str],
        )
    pkg = pkg_out / "fedramp20x-package.json"
    if not pkg.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="fedramp20x-package.json missing after build-20x-package",
            commands=[cmd1, cmd2_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"package built under {_safe_rel(pkg_out, ctx.repo_root)}",
        artifacts=[pkg, pkg_out / "reports" / "assessor" / "ksi-by-ksi-assessment.md"],
        commands=[cmd1, cmd2_str],
    )


def step_tracker_import(ctx: Context) -> StepResult:
    step = _start_step("tracker_import", _step_titles()["tracker_import"])
    started = time.time()
    out = ctx.tracker_dirs["import_only"]
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "agent.py", "import-assessment-tracker",
        "--input", str(ctx.tracker_csv),
        "--output", str(out),
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(cmd[1:])
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"import-assessment-tracker exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    items = out / "tracker_items.json"
    gaps = out / "evidence_gaps.json"
    if not items.is_file() or not gaps.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"missing required outputs: {items.name}, {gaps.name}",
            commands=[cmd_str],
        )
    try:
        bundle = json.loads(items.read_text(encoding="utf-8"))
        rows = bundle.get("rows") or bundle.get("tracker_items") or []
        gaps_doc = json.loads(gaps.read_text(encoding="utf-8"))
        gap_rows = gaps_doc.get("evidence_gaps") or []
        info_rows = gaps_doc.get("informational_tracker_items") or []
    except Exception as e:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"could not parse tracker outputs: {e}",
            commands=[cmd_str],
        )
    if not rows:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="tracker_items.json contains no rows",
            commands=[cmd_str],
        )
    coverage_holds = bool(gaps_doc.get("coverage_invariant_holds", False))
    if len(gap_rows) + len(info_rows) != len(rows):
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=(
                f"coverage invariant broken: rows={len(rows)} gaps+info="
                f"{len(gap_rows) + len(info_rows)}"
            ),
            commands=[cmd_str],
        )
    if not coverage_holds:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="coverage_invariant_holds = false in evidence_gaps.json",
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"{len(rows)} tracker rows -> {len(gap_rows)} gaps + {len(info_rows)} informational",
        artifacts=[items, gaps, out / "auditor_questions.md"],
        commands=[cmd_str],
    )


def step_tracker_gap_classification(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("tracker_gap_classification", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("tracker_gap_classification", _step_titles()["tracker_gap_classification"])
    started = time.time()
    out = ctx.tracker_dirs["classify_only"]
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "agent.py", "assess-tracker",
        "--input", str(ctx.tracker_csv),
        "--output-dir", str(out),
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(cmd[1:])
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"assess-tracker exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    eval_path = out / "tracker_gap_eval_results.json"
    if not eval_path.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="tracker_gap_eval_results.json missing",
            commands=[cmd_str],
        )
    try:
        eval_doc = json.loads(eval_path.read_text(encoding="utf-8"))
    except Exception as e:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"tracker_gap_eval_results.json not parseable: {e}",
            commands=[cmd_str],
        )
    groups = eval_doc.get("groups") or []
    if not groups:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="tracker eval produced no groups",
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"TRACKER_EVIDENCE_GAP_ANALYSIS = {eval_doc.get('result', '?')} across {len(groups)} groups",
        artifacts=[
            eval_path,
            out / "tracker_gap_report.md",
            out / "tracker_gap_matrix.csv",
            out / "auditor_questions.md",
        ],
        commands=[cmd_str],
    )


def step_tracker_to_20x_package(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("tracker_to_20x_package", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("tracker_to_20x_package", _step_titles()["tracker_to_20x_package"])
    started = time.time()
    out = ctx.tracker_dirs["tracker_to_20x"]
    out.mkdir(parents=True, exist_ok=True)
    pkg = out / "package_tracker"
    cmd = [
        sys.executable, "agent.py", "tracker-to-20x",
        "--input", str(ctx.tracker_csv),
        "--config", str(ctx.config_dir),
        "--output-dir", str(out),
        "--package-output", str(pkg),
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(cmd[1:])
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"tracker-to-20x exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    pkg_json = pkg / "fedramp20x-package.json"
    if not pkg_json.is_file():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"missing {pkg_json}",
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"tracker-to-20x package under {_safe_rel(pkg, ctx.repo_root)}",
        artifacts=[
            pkg_json,
            out / "tracker_gap_report.md",
            out / "auditor_questions.md",
            out / "poam.csv",
            pkg / "reports" / "assessor" / "ksi-by-ksi-assessment.md",
            pkg / "reports" / "executive" / "executive-summary.md",
            pkg / "reports" / "agency-ao" / "ao-risk-brief.md",
        ],
        commands=[cmd_str],
    )


def step_agent_loop_tracker_to_20x(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("agent_loop_tracker_to_20x", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("agent_loop_tracker_to_20x", _step_titles()["agent_loop_tracker_to_20x"])
    started = time.time()
    out = ctx.tracker_dirs["agent_run"]
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "agent.py", "run-agent",
        "--workflow", "tracker-to-20x",
        "--input", str(ctx.tracker_csv),
        "--output-dir", str(out),
    ]
    proc = run_command(ctx, cmd)
    cmd_str = " ".join(cmd[1:])
    if proc.returncode != 0:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"run-agent --workflow tracker-to-20x exited {proc.returncode}",
            details=[_shorten(proc.stderr, 1500)],
            commands=[cmd_str],
        )
    trace_path = out / "agent_run_trace.json"
    summary_path = out / "agent_run_summary.md"
    pkg_json = out / "package_tracker" / "fedramp20x-package.json"
    missing = [p for p in (trace_path, summary_path, pkg_json) if not p.is_file()]
    if missing:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"missing required artifacts: {', '.join(p.name for p in missing)}",
            commands=[cmd_str],
        )
    try:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
    except Exception as e:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"agent_run_trace.json not parseable: {e}",
            commands=[cmd_str],
        )
    overall = str(trace.get("overall_status") or "").lower()
    tasks = trace.get("tasks") or []
    failed = [t for t in tasks if t.get("status") == "failed"]
    if overall != "success" or failed:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=(
                f"workflow status={overall} with {len(failed)} failed task(s): "
                + ", ".join(t.get("task_id", "?") for t in failed)
            ),
            commands=[cmd_str],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"15-task DAG: success ({len(tasks)} tasks)",
        artifacts=[trace_path, summary_path, pkg_json],
        commands=[cmd_str],
    )


def _candidate_packages(ctx: Context) -> list[Path]:
    """Every fedramp20x-package.json this run produced (in priority order)."""
    candidates = [
        ctx.output_root / "package_readiness" / "fedramp20x-package.json",
        ctx.tracker_dirs["tracker_to_20x"] / "package_tracker" / "fedramp20x-package.json",
        ctx.tracker_dirs["agent_run"] / "package_tracker" / "fedramp20x-package.json",
    ]
    return [p for p in candidates if p.is_file()]


def step_package_schema_validation(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("package_schema_validation", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("package_schema_validation", _step_titles()["package_schema_validation"])
    started = time.time()
    pkgs = _candidate_packages(ctx)
    if not pkgs:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="no fedramp20x-package.json candidates produced upstream",
        )
    cmds: list[str] = []
    failures: list[str] = []
    for pkg in pkgs:
        cmd = [
            sys.executable, "agent.py", "validate-20x-package",
            "--package", str(pkg),
            "--schemas", str(ctx.schemas_dir),
        ]
        cmds.append(" ".join(cmd[1:]))
        proc = run_command(ctx, cmd)
        if proc.returncode != 0:
            failures.append(
                f"{_safe_rel(pkg, ctx.repo_root)}: rc={proc.returncode} stderr={_shorten(proc.stderr, 400)}"
            )
    if failures:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"{len(failures)} package(s) failed schema validation",
            details=failures,
            commands=cmds,
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"{len(pkgs)} package(s) validated against schemas/ : OK",
        artifacts=pkgs,
        commands=cmds,
    )


def step_narrative_validation(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("narrative_validation", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("narrative_validation", _step_titles()["narrative_validation"])
    started = time.time()
    from core.failure_narrative_contract import (
        validate_eval_results_fail_partial_contracts,
    )
    eval_files = [
        ctx.assessment_dirs["fixture"] / "eval_results.json",
        ctx.tracker_dirs["tracker_to_20x"] / "eval_results.json",
        ctx.tracker_dirs["agent_run"] / "eval_results.json",
    ]
    failures: list[str] = []
    cmds: list[str] = []
    checked: list[Path] = []
    for ef in eval_files:
        if not ef.is_file():
            continue
        checked.append(ef)
        try:
            doc = json.loads(ef.read_text(encoding="utf-8"))
        except Exception as e:
            failures.append(f"{ef}: parse error {e}")
            continue
        errs = validate_eval_results_fail_partial_contracts(doc)
        if errs:
            failures.append(f"{_safe_rel(ef, ctx.repo_root)}: {len(errs)} contract violation(s)")
            failures.extend(f"  - {e}" for e in errs[:8])
    # scripts/validate_outputs.py asserts a complete cloud bundle (non-empty
    # evidence_graph, real semantic events, etc.) and is therefore only
    # meaningful for the cloud fixture assessment. Tracker-derived scenarios
    # are intentionally event-empty (they describe evidence *gaps*), so we
    # skip the validator there to avoid spurious failures while still keeping
    # the FAIL/PARTIAL narrative contract above as the binding gate.
    cloud_dir = ctx.assessment_dirs["fixture"]
    if cloud_dir.is_dir():
        cmd = [
            sys.executable, "scripts/validate_outputs.py",
            "--output-dir", str(cloud_dir),
        ]
        cmds.append(" ".join(cmd[1:]))
        proc = run_command(ctx, cmd)
        if proc.returncode != 0:
            failures.append(
                f"validate_outputs.py {_safe_rel(cloud_dir, ctx.repo_root)}: rc={proc.returncode}\n  "
                f"{_shorten((proc.stdout or '') + (proc.stderr or ''), 600)}"
            )
    if failures:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"{len(failures)} narrative-contract or output-validator failure(s)",
            details=failures,
            commands=cmds,
        )
    if not checked:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="no eval_results.json files were available to check",
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"{len(checked)} eval_results.json passed FAIL/PARTIAL contract + validator",
        artifacts=checked,
        commands=cmds,
    )


def step_reconciliation_validation(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("reconciliation_validation", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("reconciliation_validation", _step_titles()["reconciliation_validation"])
    started = time.time()
    pkgs = _candidate_packages(ctx)
    if not pkgs:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary="no packages to reconcile",
        )
    cmds: list[str] = []
    failures: list[str] = []
    for pkg in pkgs:
        # reports/ live at the package directory itself.
        reports_root = pkg.parent
        cmd = [
            sys.executable, "agent.py", "reconcile-20x",
            "--package", str(pkg),
            "--reports", str(reports_root),
        ]
        cmds.append(" ".join(cmd[1:]))
        proc = run_command(ctx, cmd)
        if proc.returncode != 0:
            failures.append(
                f"{_safe_rel(pkg, ctx.repo_root)}: rc={proc.returncode} {_shorten(proc.stdout + proc.stderr, 400)}"
            )
    if failures:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"{len(failures)} package(s) failed reconciliation",
            details=failures,
            commands=cmds,
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"REC-001..REC-010 PASS on {len(pkgs)} package(s)",
        artifacts=pkgs,
        commands=cmds,
    )


def step_web_sample_data_preparation(ctx: Context) -> StepResult:
    skip = _skip_if_prereqs_failed("web_sample_data_preparation", _RESULTS)
    if skip is not None:
        return skip
    step = _start_step("web_sample_data_preparation", _step_titles()["web_sample_data_preparation"])
    started = time.time()
    sd = ctx.repo_root / "web" / "sample-data" / "tracker"
    src = ctx.tracker_dirs["agent_run"]
    if not src.is_dir():
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"agent_run output {src} missing",
        )
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "scenario_from_tracker").mkdir(exist_ok=True)
    (sd / "package_tracker").mkdir(exist_ok=True)
    copied: list[Path] = []
    file_pairs = [
        (src / "agent_run_trace.json", sd / "agent_run_trace.json"),
        (src / "agent_run_summary.md", sd / "agent_run_summary.md"),
        (src / "eval_results.json", sd / "eval_results.json"),
        (src / "tracker_gap_eval_results.json", sd / "tracker_gap_eval_results.json"),
        (src / "tracker_gap_report.md", sd / "tracker_gap_report.md"),
        (src / "tracker_gap_matrix.csv", sd / "tracker_gap_matrix.csv"),
        (src / "auditor_questions.md", sd / "auditor_questions.md"),
        (src / "poam.csv", sd / "poam.csv"),
        (src / "tracker_poam.csv", sd / "tracker_poam.csv"),
    ]
    for s_p, d_p in file_pairs:
        if s_p.is_file():
            shutil.copy2(s_p, d_p)
            copied.append(d_p)
    scen_src = src / "scenario_from_tracker"
    if scen_src.is_dir():
        for name in ("tracker_items.json", "evidence_gaps.json", "auditor_questions.md"):
            sp = scen_src / name
            if sp.is_file():
                dp = sd / "scenario_from_tracker" / name
                shutil.copy2(sp, dp)
                copied.append(dp)
    pkg_src = src / "package_tracker"
    if pkg_src.is_dir():
        pkg_dst = sd / "package_tracker"
        # Replace the package subtree wholesale to avoid stale files.
        for sub in ("evidence", "reports"):
            d = pkg_dst / sub
            if d.exists():
                shutil.rmtree(d)
        spkg = pkg_src / "fedramp20x-package.json"
        if spkg.is_file():
            shutil.copy2(spkg, pkg_dst / "fedramp20x-package.json")
            copied.append(pkg_dst / "fedramp20x-package.json")
        for sub in ("evidence", "reports"):
            ssub = pkg_src / sub
            if ssub.is_dir():
                shutil.copytree(ssub, pkg_dst / sub)
    _redact_sample_data_paths(sd, ctx.repo_root)
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=f"web/sample-data/tracker refreshed ({len(copied)} top-level files)",
        artifacts=copied[:8],
    )


def _redact_sample_data_paths(root: Path, repo_root: Path) -> None:
    """Keep committed web sample data portable and free of local temp/user paths."""
    import re

    replacements: list[tuple[re.Pattern[str], str]] = [
        (re.compile(re.escape(str(repo_root.resolve()))), "<repo>"),
        (re.compile(r"/private/var/folders/[^\s\"`]+/validation_run/agent_run_tracker"), "<tmp>/validation_run/agent_run_tracker"),
        (re.compile(r"/private/var/folders/[^\s\"`]+/pytest-of-[^/\s\"`]+/[^\s\"`]+"), "<tmp>/pytest-run"),
    ]
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        new = text
        for pattern, replacement in replacements:
            new = pattern.sub(replacement, new)
        if new != text:
            path.write_text(new, encoding="utf-8")


# ---------------------------------------------------------------------------
# Step 13: AI fallback explanation test
# ---------------------------------------------------------------------------

# Phrases the *output* must NOT contain even when the input lacks evidence
# (regex). The hallucination-contract sanitizer in ai/reasoning.py rewrites
# them into "**missing evidence**" markers; we use these patterns to verify the
# sanitizer is in effect in the produced text.
_HALLUCINATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "alert fired claim",
        re.compile(
            r"\balert(?:s)?\s+(?:was|were|is|are|got|has\s+been|have\s+been)?\s*"
            r"(?:fired|firing|triggered|paged|sent)\b",
            re.I,
        ),
    ),
    (
        "ticket created claim",
        re.compile(
            r"\b(?:ticket\s+[A-Z][\w-]*\d+|(?:JIRA|INC|SNOW|TKT|CHG|SR)[-_ ]?\d{2,})\s+"
            r"(?:was\s+|were\s+)?(?:filed|created|opened|raised|generated|submitted)\b",
            re.I,
        ),
    ),
    (
        "centralized log claim",
        re.compile(
            r"\b(?:splunk|cloudwatch|sentinel|datadog)\s+(?:contains|holds|has\s+the)\b[^\n]{0,80}\baudit\s+log",
            re.I,
        ),
    ),
)


def _fallback_classify_check(ctx: Context) -> tuple[str, str]:
    from ai import classify_ambiguous_row

    row = {
        "row_index": 99,
        "request_text": "Provide centralized audit log aggregation example covering AU-6.",
        "controls": ["AU-6"],
    }
    out = classify_ambiguous_row(
        tracker_row=row,
        deterministic_classification={"gap_type": "unknown", "severity": "low"},
    )
    if out.source != "deterministic_fallback":
        return FAIL, f"classify_ambiguous_row source = {out.source} (expected deterministic_fallback when AI_API_KEY unset)"
    return PASS, f"classify_ambiguous_row source=deterministic_fallback gap_type={out.gap_type}"


def _fallback_assessor_check(ctx: Context) -> tuple[str, str, str]:
    from ai import explain_for_assessor

    rec = {
        "eval_id": "AU6_CENTRALIZED_LOG_COVERAGE",
        "result": "FAIL",
        "severity": "high",
        "gap": "no central logs",
        "control_refs": ["AU-6"],
    }
    out = explain_for_assessor(eval_record=rec)
    if out.source != "deterministic_fallback":
        return (
            FAIL,
            f"explain_for_assessor source = {out.source} (expected deterministic_fallback when AI_API_KEY unset)",
            out.body,
        )
    return PASS, "explain_for_assessor returned ExplanationResponse with source=deterministic_fallback", out.body


def _fallback_auditor_response_check(ctx: Context) -> tuple[str, str, str]:
    from ai import draft_auditor_response

    out = draft_auditor_response(
        question="Did the alert fire and was a ticket created when the suspicious S3 access happened?",
        evidence_gap={
            "gap_id": "GAP-AU-6-XX",
            "controls": ["AU-6", "SI-4"],
            "gap_type": "alert_sample_missing",
            "severity": "high",
            "title": "No example alert evidence",
            "description": "We have no sample_alert_ref or last_fired in the bundle.",
        },
    )
    if out.source != "deterministic_fallback":
        return FAIL, f"draft_auditor_response source = {out.source}", out.response_md
    return PASS, "draft_auditor_response returned AuditorResponseDraft with source=deterministic_fallback", out.response_md


def _hallucination_contract_check(samples: list[str]) -> list[str]:
    """Return a list of contract failures across the supplied sample texts."""
    failures: list[str] = []
    for sample in samples:
        if not sample:
            continue
        for label, rx in _HALLUCINATION_PATTERNS:
            if rx.search(sample):
                failures.append(f"hallucination contract violated ({label}): {_shorten(sample, 240)!r}")
    return failures


def step_ai_fallback_explanation_test(ctx: Context) -> StepResult:
    step = _start_step(
        "ai_fallback_explanation_test", _step_titles()["ai_fallback_explanation_test"]
    )
    started = time.time()
    has_key = bool(os.environ.get("AI_API_KEY", "").strip())
    try:
        s1, m1 = _fallback_classify_check(ctx)
        s2, m2, body_assessor = _fallback_assessor_check(ctx)
        s3, m3, body_auditor = _fallback_auditor_response_check(ctx)
    except Exception as e:  # noqa: BLE001
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"reasoner invocation crashed: {e}",
        )
    failures = [m for s, m in ((s1, m1), (s2, m2), (s3, m3)) if s == FAIL]
    contract_violations = _hallucination_contract_check([body_assessor, body_auditor])
    if has_key and any(s == FAIL for s in (s1, s2, s3)):
        # If the operator HAS a key but the reasoner still hit fallback, that
        # is unexpected (maybe the LLM call failed). Treat it as WARN unless
        # the contract was also violated.
        status = FAIL if contract_violations else WARN
        summary_bits = ["AI_API_KEY set but reasoners returned deterministic_fallback"]
        if contract_violations:
            summary_bits.append(f"+ {len(contract_violations)} hallucination contract violation(s)")
        return _finish_step(
            step,
            started_perf=started,
            status=status,
            summary="; ".join(summary_bits),
            details=failures + contract_violations,
        )
    if contract_violations:
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"{len(contract_violations)} hallucination contract violation(s) in reasoner output",
            details=contract_violations,
        )
    if not has_key:
        # Required: WARN (not FAIL) when AI_API_KEY missing AND fallback works.
        return _finish_step(
            step,
            started_perf=started,
            status=WARN,
            summary=(
                "AI_API_KEY not set; deterministic fallback path verified across "
                "classify_ambiguous_row + explain_for_assessor + draft_auditor_response "
                "(hallucination contract held)"
            ),
            details=[m1, m2, m3],
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary="AI reasoners verified (LLM live or fallback consistent); hallucination contract held",
        details=[m1, m2, m3],
    )


# ---------------------------------------------------------------------------
# Step 15: Secret scan of generated outputs
#
# Delegates to :mod:`scripts.scan_generated_outputs` for the canonical
# pattern catalog and allowlist semantics. The scan covers the
# ``validation_run/`` directory (everything this script produced) plus the
# repo's standard generated-output directories so a fresh run also catches
# anything written by the upstream steps.
# ---------------------------------------------------------------------------


def _safe_rel(path: Path, root: Path) -> str:
    """``Path.relative_to`` but never raises — falls back to the absolute path."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def step_secret_scan_generated_outputs(ctx: Context) -> StepResult:
    step = _start_step("secret_scan_generated_outputs", _step_titles()["secret_scan_generated_outputs"])
    started = time.time()
    try:
        from scripts import scan_generated_outputs as scanner
    except Exception as e:  # noqa: BLE001
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=f"could not import scripts.scan_generated_outputs: {e}",
        )
    paths: list[Path] = [ctx.output_root]
    for d in scanner.DEFAULT_SCAN_PATHS:
        candidate = ctx.repo_root / d
        if candidate.exists():
            paths.append(candidate)
    result = scanner.scan_paths(
        paths,
        base=ctx.repo_root,
        scan_emails=False,
    )
    rep = result.reportable
    cmds = ["scripts/scan_generated_outputs.py --paths " + " ".join(result.paths_scanned)]
    if rep:
        details = [
            f"{f.file}:{f.line}:{f.column} :: {f.category} :: {f.preview}"
            for f in rep[:25]
        ]
        if len(rep) > 25:
            details.append(f"...and {len(rep) - 25} more")
        return _finish_step(
            step,
            started_perf=started,
            status=FAIL,
            summary=(
                f"{len(rep)} reportable secret-shaped value(s) in generated outputs "
                f"({len(result.allowlisted)} allowlisted)"
            ),
            details=details,
            commands=cmds,
        )
    return _finish_step(
        step,
        started_perf=started,
        status=PASS,
        summary=(
            f"scan_generated_outputs: {result.files_scanned} file(s) across "
            f"{len(result.paths_scanned)} path(s) — no reportable findings "
            f"({len(result.allowlisted)} allowlisted)"
        ),
        commands=cmds,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# Module-level dict so each step can consult upstream results for SKIP gating.
_RESULTS: dict[str, StepResult] = {}


_STEP_ORDER: tuple[tuple[str, Any], ...] = (
    ("unit_tests", step_unit_tests),
    ("reference_repo_inventory", step_reference_repo_inventory),
    ("reference_samples_manifest_validate", step_reference_samples_manifest_validate),
    ("reference_reuse_audit", step_reference_reuse_audit),
    ("adapter_prowler_reference_sample", step_adapter_prowler_reference_sample),
    ("adapter_cloudsploit_reference_sample", step_adapter_cloudsploit_reference_sample),
    ("adapter_ocsf_reference_sample", step_adapter_ocsf_reference_sample),
    ("public_exposure_policy_validation", step_public_exposure_policy_validation),
    ("evidence_graph_vocabulary_validation", step_evidence_graph_vocabulary_validation),
    ("fedramp20x_reference_package_validation", step_fedramp20x_reference_package_validation),
    ("reference_gap_matrix_document", step_reference_gap_matrix_document),
    ("reference_traceability_document", step_reference_traceability_document),
    ("fixture_cloud_assessment", step_fixture_cloud_assessment),
    ("agentic_risk_assessment", step_agentic_risk_assessment),
    ("20x_readiness_assessment", step_20x_readiness_assessment),
    ("tracker_import", step_tracker_import),
    ("tracker_gap_classification", step_tracker_gap_classification),
    ("tracker_to_20x_package", step_tracker_to_20x_package),
    ("agent_loop_tracker_to_20x", step_agent_loop_tracker_to_20x),
    ("package_schema_validation", step_package_schema_validation),
    ("narrative_validation", step_narrative_validation),
    ("reconciliation_validation", step_reconciliation_validation),
    ("web_sample_data_preparation", step_web_sample_data_preparation),
    ("ai_fallback_explanation_test", step_ai_fallback_explanation_test),
    ("secret_scan_generated_outputs", step_secret_scan_generated_outputs),
)


def run_all(ctx: Context) -> dict[str, StepResult]:
    _RESULTS.clear()
    print(f"validate_everything : output_root = {ctx.output_root}")
    for step_id, fn in _STEP_ORDER:
        title = _step_titles()[step_id]
        print(f"  ▶ {title}")
        sys.stdout.flush()
        try:
            res = fn(ctx)
        except Exception as e:  # noqa: BLE001
            res = StepResult(
                step_id=step_id,
                title=title,
                status=FAIL,
                summary=f"unhandled exception: {type(e).__name__}: {e}",
                started_at=_now_iso(),
                completed_at=_now_iso(),
            )
        _RESULTS[step_id] = res
        if res.status == FAIL:
            record_failure(ctx, res)
        marker = {PASS: "✓", WARN: "!", FAIL: "✗", SKIP: "·"}[res.status]
        print(f"    {marker} {res.status:5}  {res.summary}")
    return dict(_RESULTS)


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------


def _aggregate_status(results: dict[str, StepResult]) -> str:
    if any(r.status == FAIL for r in results.values()):
        return FAIL
    if any(r.status == WARN for r in results.values()):
        return WARN
    if all(r.status in (PASS, SKIP) for r in results.values()) and any(r.status == PASS for r in results.values()):
        return PASS
    return WARN


_DEMO_ARTIFACT_HINTS: tuple[tuple[str, list[str]], ...] = (
    ("Tracker -> 20x package report (assessor view)",
        ["tracker_to_20x/package_tracker/reports/assessor/ksi-by-ksi-assessment.md"]),
    ("Tracker -> 20x executive summary",
        ["tracker_to_20x/package_tracker/reports/executive/executive-summary.md"]),
    ("Tracker -> 20x AO risk brief",
        ["tracker_to_20x/package_tracker/reports/agency-ao/ao-risk-brief.md"]),
    ("Auditor questions derived from tracker",
        ["tracker_to_20x/auditor_questions.md", "scenario_from_tracker_import/auditor_questions.md"]),
    ("Tracker gap report",
        ["tracker_to_20x/tracker_gap_report.md", "scenario_from_tracker_classify/tracker_gap_report.md"]),
    ("Agent loop run trace + summary",
        ["agent_run_tracker/agent_run_trace.json", "agent_run_tracker/agent_run_summary.md"]),
    ("20x readiness package",
        ["package_readiness/fedramp20x-package.json"]),
    ("Cloud fixture assessment evals",
        ["fixture_assessment/eval_results.json"]),
    ("Agentic risk evals + agent security bundle",
        ["agentic_assessment/agent_eval_results.json", "agentic_assessment/agent_risk_report.md"]),
    ("Web explorer (after this run)",
        ["../web/index.html (open via `python scripts/serve_web.py`)"]),
)


def write_summary_json(ctx: Context, results: dict[str, StepResult]) -> Path:
    path = ctx.output_root / "validation_summary.json"
    summary_data = {
        "schema_version": "1.0",
        "tool": "validate_everything",
        "started_at": ctx.started_at.isoformat(timespec="seconds"),
        "completed_at": _now_iso(),
        "tracker_input": str(ctx.tracker_csv),
        "output_root": str(ctx.output_root),
        "overall_status": _aggregate_status(results),
        "ai_api_key_present": bool(os.environ.get("AI_API_KEY", "").strip()),
        "aws_credentials_present": bool(
            os.environ.get("AWS_ACCESS_KEY_ID")
            or os.environ.get("AWS_PROFILE")
            or os.environ.get("AWS_SESSION_TOKEN")
        ),
        "steps": [r.to_dict() for _id, r in results.items()],
        "demo_artifacts": _resolve_demo_artifacts(ctx),
    }
    path.write_text(json.dumps(summary_data, indent=2) + "\n", encoding="utf-8")
    return path


def _resolve_demo_artifacts(ctx: Context) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for label, rels in _DEMO_ARTIFACT_HINTS:
        for rel in rels:
            full = (ctx.output_root / rel) if not rel.startswith("../") else (ctx.output_root.parent / rel[3:].split(" ")[0])
            if "(" in rel:
                # Hint string like "../web/index.html (open via ...)" — keep verbatim.
                out.append({"label": label, "path": rel})
                continue
            if full.is_file() or full.is_dir():
                out.append({"label": label, "path": _safe_rel(full, ctx.repo_root)})
    return out


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_reference_validation_summary_md(
    ctx: Context, results: dict[str, StepResult]
) -> Path:
    """Reference-only rollup (gates, adapter samples, doc presence)."""
    path = ctx.output_root / "reference_validation_summary.md"
    ref_results = {k: v for k, v in results.items() if k in _REFERENCE_VALIDATION_SUMMARY_STEP_IDS}
    overall_ref = (
        FAIL
        if any(r.status == FAIL for r in ref_results.values())
        else WARN
        if any(r.status == WARN for r in ref_results.values())
        else PASS
    )
    buf = io.StringIO()
    buf.write("# Reference validation summary\n\n")
    buf.write(f"- **Completed:** {_now_iso()}\n")
    buf.write(f"- **Reference subset status:** **{overall_ref}**\n")
    buf.write(f"- **Tracker input:** `{_safe_rel(ctx.tracker_csv, ctx.repo_root)}`\n\n")
    buf.write("## Rules\n\n")
    buf.write(
        "- Missing **optional** `reference_samples` adapter input file → **WARN** "
        f"(see `{_OPTIONAL_REFERENCE_SAMPLE_README}`).\n"
    )
    buf.write(
        "- **Adapter pytest fails** while the sample file **is** present → **FAIL**.\n"
    )
    buf.write(
        "- **Runtime import** from `reference_samples` or `reference.*` under "
        "product code + **license/manifest parity** → **FAIL** "
        "(`scripts/audit_reference_reuse.py`).\n\n"
    )
    buf.write("## Step results (reference-backed)\n\n")
    buf.write("| # | Step | Status | Summary |\n")
    buf.write("|---|------|--------|---------|\n")
    for i, (sid, res) in enumerate(ref_results.items(), start=1):
        title = res.title.split(". ", 1)[-1] if ". " in res.title else res.title
        buf.write(f"| {i} | {title} | **{res.status}** | {_md_escape(res.summary)} |\n")
    fails = [r for r in ref_results.values() if r.status == FAIL]
    if fails:
        buf.write("\n## Failures\n\n")
        for r in fails:
            buf.write(f"### {r.title}\n\n{r.summary}\n\n")
    warns = [r for r in ref_results.values() if r.status == WARN]
    if warns:
        buf.write("\n## Warnings\n\n")
        for r in warns:
            buf.write(f"- **{r.title}** — {_md_escape(r.summary)}\n")
    buf.write("\n## Artifacts\n\n")
    buf.write("- `reference_reuse_audit.md` — full reuse audit report from this run.\n")
    path.write_text(buf.getvalue(), encoding="utf-8")
    return path


def write_summary_md(ctx: Context, results: dict[str, StepResult]) -> Path:
    overall = _aggregate_status(results)
    path = ctx.output_root / "validation_summary.md"
    buf = io.StringIO()
    buf.write(f"# Validation Summary — `validate_everything`\n\n")
    buf.write(f"- **Started:** {ctx.started_at.isoformat(timespec='seconds')}\n")
    buf.write(f"- **Completed:** {_now_iso()}\n")
    buf.write(f"- **Tracker input:** `{_safe_rel(ctx.tracker_csv, ctx.repo_root)}`\n")
    buf.write(f"- **Output root:** `{_safe_rel(ctx.output_root, ctx.repo_root)}`\n")
    buf.write(f"- **Overall status:** **{overall}**\n")
    buf.write(f"- **AI_API_KEY present:** {'yes' if os.environ.get('AI_API_KEY', '').strip() else 'no (deterministic-only mode)'}\n")
    buf.write(f"- **AWS credentials present:** {'yes' if os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_PROFILE') else 'no (live AWS path skipped → WARN, not FAIL, by design)'}\n\n")
    buf.write("## Step results\n\n")
    buf.write("| # | Step | Status | Summary |\n")
    buf.write("|---|------|--------|---------|\n")
    for i, (sid, res) in enumerate(results.items(), start=1):
        title = res.title.split(". ", 1)[-1] if ". " in res.title else res.title
        buf.write(f"| {i} | {title} | **{res.status}** | {_md_escape(res.summary)} |\n")
    failures = [r for r in results.values() if r.status == FAIL]
    warns = [r for r in results.values() if r.status == WARN]
    if failures:
        buf.write("\n## Failures (FAIL)\n\n")
        for r in failures:
            buf.write(f"### {r.title}\n\n")
            buf.write(f"- **summary:** {_md_escape(r.summary)}\n")
            for d in r.details[:8]:
                buf.write(f"  - {_md_escape(_shorten(d, 400))}\n")
            buf.write("\n")
    if warns:
        buf.write("\n## Warnings (WARN)\n\n")
        for r in warns:
            buf.write(f"- **{r.title}** — {_md_escape(r.summary)}\n")
    buf.write("\n## Open these for the demo\n\n")
    for entry in _resolve_demo_artifacts(ctx):
        buf.write(f"- **{entry['label']}** — `{entry['path']}`\n")
    buf.write("\n## Logs\n\n")
    buf.write(f"- `commands.log` — every shell invocation with rc + duration\n")
    buf.write(f"- `failures.log` — full detail on every FAIL\n")
    buf.write(f"- `validation_summary.json` — machine-readable copy of this report\n")
    buf.write(f"- `reference_validation_summary.md` — reference gates + adapter sample rollup\n")
    buf.write(f"- `reference_reuse_audit.md` — output from `audit_reference_reuse.py` (step 4)\n")
    path.write_text(buf.getvalue(), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Comprehensive end-to-end validation of the Observable Security Agent.",
    )
    p.add_argument(
        "--tracker",
        type=Path,
        required=True,
        help="Path to a FedRAMP assessment tracker (CSV/TSV/text).",
    )
    p.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Directory under which every artifact + log will be written.",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=REPO_ROOT / "config",
        help="FedRAMP / agent config dir (default: ./config)",
    )
    p.add_argument(
        "--schemas",
        type=Path,
        default=REPO_ROOT / "schemas",
        help="JSON Schema dir (default: ./schemas)",
    )
    p.add_argument(
        "--skip-pytest",
        action="store_true",
        help="Skip step 1 (full unit test suite). Recorded as WARN, never PASS.",
    )
    p.add_argument(
        "--fast-pytest",
        action="store_true",
        help="Pass -x and --no-header to pytest (still hard-fails on first error).",
    )
    p.add_argument(
        "--keep-existing-output",
        action="store_true",
        help="Do NOT clear --output-root before the run (default is to start clean).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.tracker.is_file():
        print(f"ERROR: tracker file not found: {args.tracker}", file=sys.stderr)
        return 2
    output_root = args.output_root.resolve()
    if output_root.exists() and not args.keep_existing_output:
        # Clear non-log children. We never delete the user's repo root.
        for child in output_root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    output_root.mkdir(parents=True, exist_ok=True)
    cmd_log = output_root / "commands.log"
    fail_log = output_root / "failures.log"
    cmd_log.write_text(f"# validate_everything commands log — started {_now_iso()}\n", encoding="utf-8")
    fail_log.write_text(f"# validate_everything failures log — started {_now_iso()}\n", encoding="utf-8")

    ctx = Context(
        tracker_csv=args.tracker.resolve(),
        output_root=output_root,
        repo_root=REPO_ROOT,
        config_dir=args.config.resolve(),
        schemas_dir=args.schemas.resolve(),
        started_at=_dt.datetime.now(tz=_dt.timezone.utc),
        cmd_log=cmd_log,
        fail_log=fail_log,
        skip_pytest=args.skip_pytest,
        fast_pytest=args.fast_pytest,
    )

    results = run_all(ctx)
    json_path = write_summary_json(ctx, results)
    md_path = write_summary_md(ctx, results)
    ref_md_path = write_reference_validation_summary_md(ctx, results)
    overall = _aggregate_status(results)
    counts = {s: sum(1 for r in results.values() if r.status == s) for s in (PASS, WARN, FAIL, SKIP)}

    print()
    print(
        f"OVERALL: {overall}  "
        f"(PASS={counts[PASS]} WARN={counts[WARN]} FAIL={counts[FAIL]} SKIP={counts[SKIP]})"
    )
    print(f"  json    : {_safe_rel(json_path, REPO_ROOT)}")
    print(f"  md      : {_safe_rel(md_path, REPO_ROOT)}")
    print(f"  ref md  : {_safe_rel(ref_md_path, REPO_ROOT)}")
    print(f"  cmd log : {_safe_rel(cmd_log, REPO_ROOT)}")
    print(f"  fail log: {_safe_rel(fail_log, REPO_ROOT)}")
    return 0 if overall in (PASS, WARN) else 1


if __name__ == "__main__":
    raise SystemExit(main())
