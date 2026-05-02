"""Tests for ``scripts/validate_everything.py``.

Covers the rule semantics (PASS/WARN/FAIL/SKIP), each pure helper, and an
end-to-end smoke run against the bundled sample tracker. The smoke test
expects the script to exit 0 with overall WARN (no ``AI_API_KEY``) and to
write the four documented output files.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from importlib import util as _ilu
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "validate_everything.py"


def _load_module():
    if "validate_everything" in sys.modules:
        return sys.modules["validate_everything"]
    spec = _ilu.spec_from_file_location("validate_everything", SCRIPT)
    assert spec and spec.loader
    mod = _ilu.module_from_spec(spec)
    # Register before exec so dataclasses can resolve cls.__module__ during
    # class construction.
    sys.modules["validate_everything"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_module_loads_and_exports_expected_symbols() -> None:
    mod = _load_module()
    for name in (
        "PASS",
        "WARN",
        "FAIL",
        "SKIP",
        "Context",
        "StepResult",
        "run_all",
        "main",
        "_aggregate_status",
        "_HALLUCINATION_PATTERNS",
        "_REF_IMPORT_RE",
        "write_reference_validation_summary_md",
        "step_secret_scan_generated_outputs",
    ):
        assert hasattr(mod, name), f"module missing attribute {name}"


def test_25_step_order_is_complete_and_in_required_sequence() -> None:
    mod = _load_module()
    expected = [
        "unit_tests",
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
        "fixture_cloud_assessment",
        "agentic_risk_assessment",
        "20x_readiness_assessment",
        "tracker_import",
        "tracker_gap_classification",
        "tracker_to_20x_package",
        "agent_loop_tracker_to_20x",
        "package_schema_validation",
        "narrative_validation",
        "reconciliation_validation",
        "web_sample_data_preparation",
        "ai_fallback_explanation_test",
        "secret_scan_generated_outputs",
    ]
    actual = [sid for sid, _fn in mod._STEP_ORDER]
    assert actual == expected
    titles = mod._step_titles()
    for sid in expected:
        assert sid in titles


def test_aggregate_status_priority_fail_warn_pass() -> None:
    mod = _load_module()

    def mk(status: str) -> "object":
        return mod.StepResult(step_id="s", title="t", status=status)

    assert mod._aggregate_status({"a": mk(mod.FAIL), "b": mk(mod.PASS)}) == mod.FAIL
    assert mod._aggregate_status({"a": mk(mod.WARN), "b": mk(mod.PASS)}) == mod.WARN
    assert mod._aggregate_status({"a": mk(mod.PASS), "b": mk(mod.SKIP)}) == mod.PASS
    # Only SKIPs (or empty) → not a clean PASS; stays WARN.
    assert mod._aggregate_status({"a": mk(mod.SKIP)}) == mod.WARN
    assert mod._aggregate_status({}) == mod.WARN


# ---------------------------------------------------------------------------
# Reference reuse audit
# ---------------------------------------------------------------------------


def test_reference_reuse_audit_passes_on_clean_repo(tmp_path: Path) -> None:
    """The repo itself must not import from reference_samples at runtime."""
    mod = _load_module()
    ctx = _make_ctx(mod, tmp_path)
    res = mod.step_reference_reuse_audit(ctx)
    assert res.status == mod.PASS, f"unexpected: {res.summary}\n{res.details}"


def test_reference_reuse_audit_flags_a_synthetic_offender(tmp_path: Path) -> None:
    mod = _load_module()
    bad = tmp_path / "fake_runtime"
    (bad / "core").mkdir(parents=True)
    rs = bad / "reference_samples"
    rs.mkdir(parents=True)
    (rs / "manifest.json").write_text(
        '{"schema_version":"1.0","description":"stub","files":[]}\n',
        encoding="utf-8",
    )
    (bad / "agent.py").write_text(
        "from reference_samples.prowler import x\n", encoding="utf-8"
    )
    (bad / "core" / "thing.py").write_text(
        "import reference_samples.ocsf as o\n", encoding="utf-8"
    )

    ctx = _make_ctx(mod, tmp_path)
    # Override repo_root so the audit scans our synthetic tree.
    ctx.repo_root = bad
    res = mod.step_reference_reuse_audit(ctx)
    assert res.status == mod.FAIL
    blob = " ".join(res.details) + res.summary
    assert "agent.py" in blob or "forbidden" in blob.lower() or "import" in blob.lower()


def test_reference_reuse_audit_also_flags_full_clone_imports(tmp_path: Path) -> None:
    """The audit must also forbid imports from the gitignored ``reference/`` clone tree."""
    mod = _load_module()
    bad = tmp_path / "fake_runtime"
    (bad / "evals").mkdir(parents=True)
    rs = bad / "reference_samples"
    rs.mkdir(parents=True)
    (rs / "manifest.json").write_text(
        '{"schema_version":"1.0","description":"stub","files":[]}\n',
        encoding="utf-8",
    )
    (bad / "agent.py").write_text(
        "from reference.prowler import api as p\n", encoding="utf-8"
    )
    (bad / "evals" / "ouch.py").write_text(
        "import reference.fixinventory as fi\n", encoding="utf-8"
    )

    ctx = _make_ctx(mod, tmp_path)
    ctx.repo_root = bad
    res = mod.step_reference_reuse_audit(ctx)
    assert res.status == mod.FAIL
    joined = " ".join(res.details) + res.summary
    assert "agent.py" in joined or "ouch" in joined or "import" in joined.lower()


def test_ref_import_regex_matches_only_real_imports() -> None:
    mod = _load_module()
    rx = mod._REF_IMPORT_RE
    # reference_samples branch
    assert rx.search("from reference_samples.prowler import x\n")
    assert rx.search("import reference_samples\n")
    assert rx.search("import reference_samples.ocsf as o\n")
    assert rx.search("    from reference_samples import a\n")  # indented
    # reference/ clone branch — only fully-qualified imports count.
    assert rx.search("from reference.prowler import api\n")
    assert rx.search("import reference.fixinventory.foo\n")
    # Bare ``import reference`` is intentionally NOT flagged: the local
    # module ``api/explain.py`` mentions the *word* "reference" in many
    # places. We only forbid the dotted form that actually pulls a clone.
    # Mention in comment / docstring must not trigger.
    assert not rx.search("# we link to reference_samples in docs only\n")
    assert not rx.search('"""reference_samples is read-only"""')
    assert not rx.search("# see reference/README.md for inspiration\n")


# ---------------------------------------------------------------------------
# Hallucination contract
# ---------------------------------------------------------------------------


def test_hallucination_patterns_match_expected_tells() -> None:
    mod = _load_module()
    samples = [
        "The alert was fired and the responder paged.",
        "Ticket JIRA-1234 was filed at 03:14 UTC.",
        "Splunk contains the audit log for this asset.",
    ]
    failures = mod._hallucination_contract_check(samples)
    # All three patterns should fire.
    assert len(failures) >= 3
    labels = " ".join(failures).lower()
    for needle in ("alert", "ticket", "centralized log"):
        assert needle in labels


def test_hallucination_contract_passes_for_grounded_text() -> None:
    mod = _load_module()
    safe = [
        "Required evidence is **missing evidence** (no sample_alert_ref).",
        "No ticket linkage was provided in tickets.json.",
        "Central logs are missing for the asset; **missing evidence**.",
    ]
    assert mod._hallucination_contract_check(safe) == []


# ---------------------------------------------------------------------------
# Secret scan
# ---------------------------------------------------------------------------


def test_secret_scan_flags_aws_key_in_normal_path(tmp_path: Path) -> None:
    """Real-shape AWS key, no FAKE/EXAMPLE/FIXTURE marker → FAIL."""
    mod = _load_module()
    out = tmp_path / "outroot"
    out.mkdir()
    (out / "report.md").write_text(
        "config:\n    aws_key: AKIAQYZGXY3HQ7P5LMNB\n", encoding="utf-8"
    )
    ctx = _make_ctx(mod, tmp_path, output_root=out)
    res = mod.step_secret_scan_generated_outputs(ctx)
    assert res.status == mod.FAIL, res.summary
    blob = " ".join(res.details)
    assert "report.md" in blob
    assert "aws_access_key_id" in blob
    assert "AKIAQYZGXY3HQ7P5LMNB" not in blob, "raw secret leaked into details"


def test_secret_scan_passes_when_match_carries_fake_marker(tmp_path: Path) -> None:
    """Same shape, but ``# FAKE`` header on adjacent line → allowlisted → PASS."""
    mod = _load_module()
    out = tmp_path / "outroot"
    out.mkdir()
    (out / "fixture_keys.txt").write_text(
        "# FAKE — for tests only\nAKIAQYZGXY3HQ7P5LMNB\n", encoding="utf-8"
    )
    ctx = _make_ctx(mod, tmp_path, output_root=out)
    res = mod.step_secret_scan_generated_outputs(ctx)
    assert res.status == mod.PASS, res.summary
    assert "allowlisted" in res.summary.lower()


def test_secret_scan_passes_when_no_secrets(tmp_path: Path) -> None:
    mod = _load_module()
    out = tmp_path / "outroot"
    out.mkdir()
    (out / "ok.md").write_text("No secrets here, just words.\n", encoding="utf-8")
    ctx = _make_ctx(mod, tmp_path, output_root=out)
    res = mod.step_secret_scan_generated_outputs(ctx)
    assert res.status == mod.PASS


def test_secret_scan_uses_external_scanner_module() -> None:
    """The validate_everything secret-scan step must delegate to
    ``scripts.scan_generated_outputs`` (not maintain a duplicate catalog)."""
    src = (REPO_ROOT / "scripts" / "validate_everything.py").read_text(encoding="utf-8")
    assert "from scripts import scan_generated_outputs as scanner" in src
    assert "scanner.scan_paths" in src
    assert "_SECRET_PATTERNS" not in src, (
        "step_secret_scan_generated_outputs must not maintain a duplicate "
        "pattern catalog — see scripts/scan_generated_outputs.py"
    )


# ---------------------------------------------------------------------------
# AI fallback explanation test (no API key path)
# ---------------------------------------------------------------------------


def test_ai_fallback_explanation_test_warns_when_no_api_key(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AI_API_KEY", raising=False)
    mod = _load_module()
    ctx = _make_ctx(mod, tmp_path)
    res = mod.step_ai_fallback_explanation_test(ctx)
    assert res.status == mod.WARN, res.summary
    assert "deterministic_fallback" in res.summary.lower() or "deterministic" in res.summary.lower()


# ---------------------------------------------------------------------------
# CLI: end-to-end smoke run (skip-pytest to keep the test fast)
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_cli_end_to_end_smoke_run_skips_pytest_and_succeeds(tmp_path: Path) -> None:
    out = tmp_path / "validation_run"
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--tracker",
        str(REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"),
        "--output-root",
        str(out),
        "--skip-pytest",
    ]
    env = {**os.environ}
    env.pop("AI_API_KEY", None)
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=600
    )
    assert proc.returncode == 0, proc.stderr + "\n" + proc.stdout

    # The required output files exist.
    for name in (
        "validation_summary.json",
        "validation_summary.md",
        "reference_validation_summary.md",
        "commands.log",
        "failures.log",
    ):
        assert (out / name).is_file(), f"missing {name}"

    summary = json.loads((out / "validation_summary.json").read_text(encoding="utf-8"))
    assert summary["overall_status"] in ("PASS", "WARN")
    # Every step must be present and have a status.
    step_ids = {s["step_id"] for s in summary["steps"]}
    assert len(step_ids) == 25
    for sid in (
        "unit_tests",
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
        "fixture_cloud_assessment",
        "agentic_risk_assessment",
        "20x_readiness_assessment",
        "tracker_import",
        "tracker_gap_classification",
        "tracker_to_20x_package",
        "agent_loop_tracker_to_20x",
        "package_schema_validation",
        "narrative_validation",
        "reconciliation_validation",
        "web_sample_data_preparation",
        "ai_fallback_explanation_test",
        "secret_scan_generated_outputs",
    ):
        assert sid in step_ids
    # No FAIL allowed in the local-only path.
    assert all(s["status"] in ("PASS", "WARN", "SKIP") for s in summary["steps"])

    # Markdown summary must include the demo artifacts section.
    md = (out / "validation_summary.md").read_text(encoding="utf-8")
    assert "## Open these for the demo" in md
    assert "Tracker -> 20x package report" in md
    # Commands log must contain at least one agent.py invocation.
    cmds = (out / "commands.log").read_text(encoding="utf-8")
    assert "agent.py" in cmds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(mod, tmp_path: Path, *, output_root: Path | None = None) -> "object":
    out = output_root or (tmp_path / "out")
    out.mkdir(parents=True, exist_ok=True)
    cmd_log = out / "commands.log"
    fail_log = out / "failures.log"
    cmd_log.touch()
    fail_log.touch()
    import datetime as _dt

    return mod.Context(
        tracker_csv=REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv",
        output_root=out,
        repo_root=REPO_ROOT,
        config_dir=REPO_ROOT / "config",
        schemas_dir=REPO_ROOT / "schemas",
        started_at=_dt.datetime.now(tz=_dt.timezone.utc),
        cmd_log=cmd_log,
        fail_log=fail_log,
    )
