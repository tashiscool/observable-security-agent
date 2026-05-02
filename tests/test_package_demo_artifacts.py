"""Tests for ``scripts/package_demo_artifacts.py``.

The packager has three contracts the tests pin down::

    1. It refuses to package when the secret-scan gate fails (and refuses to
       package even if the catalog itself accidentally pulls in a curated
       artifact that contains a secret).
    2. It produces both ``demo_artifacts.zip`` and
       ``demo_artifacts_manifest.json``; the manifest enumerates every file
       in the zip with its sha256 and category, plus skipped entries with
       reasons, plus the gate results.
    3. It silently skips missing inputs (does not error) and excludes
       always-skip paths and (by default) raw cloud evidence.
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from importlib import util as _ilu
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "package_demo_artifacts.py"


def _load_module():
    if "package_demo_artifacts" in sys.modules:
        return sys.modules["package_demo_artifacts"]
    spec = _ilu.spec_from_file_location("package_demo_artifacts", SCRIPT)
    assert spec and spec.loader
    mod = _ilu.module_from_spec(spec)
    sys.modules["package_demo_artifacts"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _make_min_repo(tmp_path: Path) -> Path:
    """Build the smallest-possible source tree that exercises every catalog
    entry kind: docs, package, reports dir, validation summary, web dir."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("# Demo project (fixture).\n", encoding="utf-8")
    docs = root / "docs"
    docs.mkdir()
    (docs / "product_positioning.md").write_text("positioning\n", encoding="utf-8")
    (docs / "why_this_is_not_reinventing_the_wheel.md").write_text("not\n", encoding="utf-8")
    (docs / "coalfire_aligned_demo_narrative.md").write_text("coalfire\n", encoding="utf-8")
    (docs / "local_repo_test_plan.md").write_text("test plan\n", encoding="utf-8")
    out = root / "output"
    out.mkdir()
    (out / "demo_walkthrough.md").write_text("walkthrough\n", encoding="utf-8")
    out_agent = root / "output_agent_run"
    out_agent.mkdir()
    (out_agent / "agent_run_summary.md").write_text("agent summary\n", encoding="utf-8")
    pkg = root / "evidence" / "package"
    pkg.mkdir(parents=True)
    (pkg / "fedramp20x-package.json").write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
    rdir = pkg / "reports" / "assessor"
    rdir.mkdir(parents=True)
    (rdir / "ksi-by-ksi-assessment.md").write_text("ksi report\n", encoding="utf-8")
    edir = pkg / "reports" / "executive"
    edir.mkdir(parents=True)
    (edir / "executive-summary.md").write_text("exec summary\n", encoding="utf-8")
    aodir = pkg / "reports" / "agency-ao"
    aodir.mkdir(parents=True)
    (aodir / "ao-risk-brief.md").write_text("ao risk\n", encoding="utf-8")
    vrun = root / "validation_run"
    vrun.mkdir()
    (vrun / "validation_summary.md").write_text("# validation summary\n", encoding="utf-8")
    (vrun / "validation_summary.json").write_text(
        json.dumps({"overall_status": "PASS", "step_counts": {"PASS": 15}}), encoding="utf-8"
    )
    web = root / "web" / "sample-data"
    web.mkdir(parents=True)
    (web / "eval_results.json").write_text(
        json.dumps({"actor": "alice@example.com"}), encoding="utf-8"
    )
    return root


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exports_expected_surface() -> None:
    mod = _load_module()
    for name in (
        "DEMO_INCLUDE_LIST",
        "ALWAYS_SKIP_BASENAMES",
        "RAW_EVIDENCE_PATH_HINTS",
        "is_excluded",
        "collect_files",
        "write_zip",
        "write_manifest",
        "package",
        "main",
        "IncludedFile",
        "SkippedEntry",
        "GateResult",
        "PackageResult",
    ):
        assert hasattr(mod, name), f"module missing {name}"


def test_demo_include_list_covers_user_spec() -> None:
    mod = _load_module()
    paths = {p for p, _kind in mod.DEMO_INCLUDE_LIST}
    required = {
        "README.md",
        "docs/product_positioning.md",
        "docs/why_this_is_not_reinventing_the_wheel.md",
        "docs/coalfire_aligned_demo_narrative.md",
        "docs/local_repo_test_plan.md",
        "output/demo_walkthrough.md",
        "output_tracker/tracker_gap_report.md",
        "output_agent_run/agent_run_summary.md",
        "evidence/package/fedramp20x-package.json",
        "evidence/package_tracker/fedramp20x-package.json",
        "reports/assessor",
        "reports/executive",
        "reports/agency-ao",
        "validation_run/validation_summary.md",
        "web/sample-data",
    }
    missing = required - paths
    assert not missing, f"DEMO_INCLUDE_LIST is missing required entries: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Exclusion rules
# ---------------------------------------------------------------------------


def test_is_excluded_blocks_always_skip_dirs() -> None:
    mod = _load_module()
    for p in (
        "foo/.git/HEAD",
        "x/__pycache__/y.pyc",
        ".venv/lib/python.so",
        "node_modules/x.js",
        "reference/whatever.md",
        "reference_samples/aws.py",
    ):
        excluded, reason = mod.is_excluded(p, allow_raw_evidence=False)
        assert excluded, f"{p} should be excluded; reason was: {reason}"


def test_is_excluded_blocks_credential_files() -> None:
    mod = _load_module()
    for p in (
        "creds.json",
        "subdir/.env",
        "subdir/.env.production",
        "id_rsa",
        "ops/id_rsa.pub",
        "tls/server.pem",
        "tls/server.key",
    ):
        excluded, reason = mod.is_excluded(p, allow_raw_evidence=False)
        assert excluded, f"{p} should be excluded; reason was: {reason}"


def test_is_excluded_blocks_raw_cloud_evidence_by_default() -> None:
    mod = _load_module()
    for p in (
        "evidence/raw/foo.json",
        "evidence/cloud_dumps/x.json",
        "evidence/aws-cli/list-buckets.json",
        "x/raw_evidence/y.json",
    ):
        excluded, reason = mod.is_excluded(p, allow_raw_evidence=False)
        assert excluded, f"{p} should be excluded by default; reason was: {reason}"
    # ...and is INCLUDED when the operator opts in.
    excluded, _ = mod.is_excluded("evidence/raw/foo.json", allow_raw_evidence=True)
    assert not excluded


def test_is_excluded_passes_curated_demo_paths() -> None:
    mod = _load_module()
    for p in (
        "README.md",
        "docs/why_this_is_not_reinventing_the_wheel.md",
        "evidence/package/reports/assessor/ksi-by-ksi-assessment.md",
        "validation_run/validation_summary.md",
        "web/sample-data/eval_results.json",
    ):
        excluded, _ = mod.is_excluded(p, allow_raw_evidence=False)
        assert not excluded, f"{p} should pass exclusion filters"


# ---------------------------------------------------------------------------
# collect_files
# ---------------------------------------------------------------------------


def test_collect_files_skips_missing_entries_silently(tmp_path: Path) -> None:
    """Missing catalog entries must be recorded, NOT raised."""
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    kept, skipped = mod.collect_files(root, allow_raw_evidence=False)
    arcs = {arc for _abs, arc in kept}
    # Required artifacts that exist in the min repo:
    for must_have in (
        "README.md",
        "docs/local_repo_test_plan.md",
        "evidence/package/fedramp20x-package.json",
        "evidence/package/reports/assessor/ksi-by-ksi-assessment.md",
        "validation_run/validation_summary.md",
        "web/sample-data/eval_results.json",
    ):
        assert must_have in arcs, f"missing arc: {must_have}"
    skipped_paths = {s.path for s in skipped}
    # output_tracker and reports/* (top-level) do not exist in the min repo
    # — they should appear in skipped, NOT raise.
    assert "output_tracker/tracker_gap_report.md" in skipped_paths
    assert all("not present" in s.reason or "expected" in s.reason for s in skipped)


def test_collect_files_excludes_dotfiles_inside_dirs(tmp_path: Path) -> None:
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    web = root / "web" / "sample-data"
    (web / "__pycache__").mkdir()
    (web / "__pycache__" / "x.pyc").write_text("junk\n", encoding="utf-8")
    (web / ".env").write_text("SECRET=xyz\n", encoding="utf-8")
    kept, _ = mod.collect_files(root, allow_raw_evidence=False)
    arcs = {arc for _abs, arc in kept}
    assert "web/sample-data/__pycache__/x.pyc" not in arcs
    assert "web/sample-data/.env" not in arcs


# ---------------------------------------------------------------------------
# package() end-to-end (with both gates skipped — those are integration)
# ---------------------------------------------------------------------------


def test_package_writes_zip_and_manifest(tmp_path: Path) -> None:
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    out_zip = tmp_path / "out" / "demo.zip"
    res = mod.package(
        source_root=root,
        output_zip=out_zip,
        skip_scan=True,
        skip_validation=True,
    )
    assert res.aborted_reason is None, res.aborted_reason
    assert out_zip.exists(), "zip not written"
    manifest_path = out_zip.with_name("demo_artifacts_manifest.json")
    assert manifest_path.exists()
    body = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Manifest schema sanity.
    for key in ("schema_version", "tool", "started_at", "completed_at", "totals", "gates", "files", "skipped"):
        assert key in body, f"manifest missing key {key}"
    assert body["totals"]["files"] == len(body["files"]) > 0
    for f in body["files"]:
        for k in ("arcname", "size", "sha256", "category"):
            assert k in f
        assert len(f["sha256"]) == 64

    # Acceptance: zip created AND manifest enumerates exactly the same files.
    with zipfile.ZipFile(out_zip) as zf:
        zip_names = set(zf.namelist())
    manifest_names = {f["arcname"] for f in body["files"]}
    assert zip_names == manifest_names, "manifest does not match zip contents"


def test_package_gate_results_recorded_in_manifest(tmp_path: Path) -> None:
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    out_zip = tmp_path / "demo.zip"
    res = mod.package(
        source_root=root,
        output_zip=out_zip,
        skip_scan=True,
        skip_validation=True,
    )
    body = json.loads(res.manifest_path.read_text(encoding="utf-8"))
    assert body["gates"]["scan_generated_outputs"]["ran"] is False
    assert body["gates"]["validate_everything"]["ran"] is False
    # The pre_zip_secret_scan ALWAYS runs (defensive scan over curated files).
    assert body["gates"]["pre_zip_secret_scan"]["ran"] is True
    assert body["gates"]["pre_zip_secret_scan"]["status"] == "PASS"


def test_package_pre_zip_scan_blocks_secret_in_curated_file(tmp_path: Path) -> None:
    """Acceptance: no secrets included.

    Even when both upstream gates are skipped, the packager runs a
    secondary scan over the files it is about to add and aborts if any
    reportable finding remains.
    """
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    # Plant a real-shape AWS key into a curated artifact.
    (root / "output" / "demo_walkthrough.md").write_text(
        "walkthrough\nAWS_KEY=AKIAQYZGXY3HQ7P5LMNB\n", encoding="utf-8"
    )
    out_zip = tmp_path / "demo.zip"
    res = mod.package(
        source_root=root,
        output_zip=out_zip,
        skip_scan=True,  # bypass the pre-flight scanner
        skip_validation=True,
    )
    assert res.aborted_reason is not None
    assert "secret" in res.aborted_reason.lower()
    assert not out_zip.exists(), "zip must NOT be written when a secret is detected"
    body = json.loads(res.manifest_path.read_text(encoding="utf-8"))
    pre = body["gates"]["pre_zip_secret_scan"]
    assert pre["status"] == "FAIL"
    findings = pre["details"]["reportable_findings"]
    assert findings and findings[0]["category"] == "aws_access_key_id"
    # Redaction contract: no full secret in the manifest.
    assert "AKIAQYZGXY3HQ7P5LMNB" not in res.manifest_path.read_text(encoding="utf-8")


def test_package_excludes_credential_file_even_if_planted(tmp_path: Path) -> None:
    """Defensive: a stray ``creds.json`` next to a curated dir must NOT get zipped."""
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    # Plant a creds.json inside web/sample-data (which IS in the catalog).
    (root / "web" / "sample-data" / "creds.json").write_text(
        json.dumps({"aws_access_key_id": "FAKE-do-not-use"}), encoding="utf-8"
    )
    out_zip = tmp_path / "demo.zip"
    res = mod.package(
        source_root=root,
        output_zip=out_zip,
        skip_scan=True,
        skip_validation=True,
    )
    assert res.aborted_reason is None
    arcs = {f.arcname for f in res.files}
    assert "web/sample-data/creds.json" not in arcs
    skipped_paths = {s.path for s in res.skipped}
    assert "web/sample-data/creds.json" in skipped_paths


def test_package_excludes_raw_cloud_evidence_by_default(tmp_path: Path) -> None:
    mod = _load_module()
    root = _make_min_repo(tmp_path)
    raw_dir = root / "evidence" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "describe-instances.json").write_text("{}\n", encoding="utf-8")
    out_zip = tmp_path / "demo.zip"
    res = mod.package(
        source_root=root,
        output_zip=out_zip,
        skip_scan=True,
        skip_validation=True,
    )
    arcs = {f.arcname for f in res.files}
    assert "evidence/raw/describe-instances.json" not in arcs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_cli_smoke_against_real_repo(tmp_path: Path) -> None:
    """Acceptance smoke: run against the real repo, both gates skipped to keep
    CI fast. Produces a valid zip + manifest."""
    out_zip = tmp_path / "demo_artifacts.zip"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source-root",
            str(REPO_ROOT),
            "--output",
            str(out_zip),
            "--skip-validation",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert out_zip.exists()
    manifest = out_zip.with_name("demo_artifacts_manifest.json")
    assert manifest.exists()
    body = json.loads(manifest.read_text(encoding="utf-8"))
    assert body["totals"]["files"] > 0
    assert body["gates"]["scan_generated_outputs"]["status"] == "PASS"
    # Acceptance: no fake secret strings inside the zip body.
    with zipfile.ZipFile(out_zip) as zf:
        for name in zf.namelist():
            data = zf.read(name)
            # Only check text files.
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            # Real-shape AWS key with no FAKE marker should NEVER appear.
            assert "AKIAQYZGXY3HQ7P5LMNB" not in text, name


@pytest.mark.slow
def test_cli_aborts_when_secret_in_curated_file(tmp_path: Path) -> None:
    """Real subprocess: planted secret → rc=1, no zip, manifest records abort."""
    root = _make_min_repo(tmp_path)
    (root / "output" / "demo_walkthrough.md").write_text(
        "x\nAKIAQYZGXY3HQ7P5LMNB\n", encoding="utf-8"
    )
    out_zip = tmp_path / "demo.zip"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source-root",
            str(root),
            "--output",
            str(out_zip),
            "--skip-scan",  # bypass pre-flight; pre_zip secondary scan still runs
            "--skip-validation",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "ABORTED" in proc.stderr or "ABORTED" in proc.stdout
    assert not out_zip.exists()
    manifest = out_zip.with_name("demo_artifacts_manifest.json")
    assert manifest.exists()


# ---------------------------------------------------------------------------
# Makefile + integration with sibling scripts
# ---------------------------------------------------------------------------


def test_makefile_exposes_package_demo_target() -> None:
    mk = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "package-demo:" in mk
    assert "scripts/package_demo_artifacts.py" in mk
    assert "package-demo" in mk.split(".PHONY:", 1)[1].splitlines()[0]


def test_packager_wires_in_scan_and_validate_scripts() -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    assert "scan_generated_outputs" in src
    assert "validate_everything" in src
    # Defensive secondary scan must use the canonical scanner module.
    assert "import scan_generated_outputs" in src
