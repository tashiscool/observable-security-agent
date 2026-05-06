#!/usr/bin/env python3
"""Bundle the demo-ready artifacts into a single zip + manifest.

The packager curates the **stakeholder-facing** outputs of the assessment
pipeline (READMEs, narrative docs, executive/AO/assessor reports, the
generated 20x package, the agent run summary, the validation summary, and
the web sample data) and writes them to ``demo_artifacts.zip`` next to a
sidecar ``demo_artifacts_manifest.json`` describing exactly what's inside.

Before zipping, two safety gates run::

    1. ``scripts/scan_generated_outputs.py`` — secret/PII scan over the
       canonical generated-output trees. A failure aborts packaging.
    2. ``scripts/validate_everything.py`` — full end-to-end validation
       (skip with ``--skip-validation``). A FAIL aborts packaging; a WARN
       is recorded in the manifest but allowed.

Excludes (always)::

    .git/                 .venv/                __pycache__/
    node_modules/         reference/            reference_samples/
    *.pem                 *.key                 id_rsa*
    creds.json            .env                  .env.*

Excludes (default-on, opt out with ``--allow-raw-evidence``)::

    evidence/raw/         evidence/cloud_dumps/  *_raw_aws.*
    evidence/aws-cli/     **/raw_evidence/

Usage::

    python scripts/package_demo_artifacts.py
    python scripts/package_demo_artifacts.py --output dist/demo.zip
    python scripts/package_demo_artifacts.py --skip-validation
    python scripts/package_demo_artifacts.py --tracker fixtures/assessment_tracker/sample_tracker.csv
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_SCRIPT = REPO_ROOT / "scripts" / "scan_generated_outputs.py"
VALIDATE_SCRIPT = REPO_ROOT / "scripts" / "validate_everything.py"


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

# Each entry is (relative_path, kind) where kind is "file" or "dir".
# Order is preserved in the manifest so the demo opens in narrative order.
DEMO_INCLUDE_LIST: tuple[tuple[str, str], ...] = (
    # Top-level docs (the "what / why" of the project).
    ("README.md", "file"),
    ("docs/product_positioning.md", "file"),
    ("docs/why_this_is_not_reinventing_the_wheel.md", "file"),
    ("docs/coalfire_aligned_demo_narrative.md", "file"),
    ("docs/local_repo_test_plan.md", "file"),
    # Generated walkthroughs and per-pipeline summaries.
    ("output/demo_walkthrough.md", "file"),
    ("output_tracker/tracker_gap_report.md", "file"),
    ("output_agent_run/agent_run_summary.md", "file"),
    # Canonical 20x packages.
    ("evidence/package/fedramp20x-package.json", "file"),
    ("evidence/package_tracker/fedramp20x-package.json", "file"),
    # Stakeholder report directories. The user spec lists these at the repo
    # root; we also pull in the canonical equivalents under each generated
    # 20x package, since those are what the assessor actually opens.
    ("reports/assessor", "dir"),
    ("reports/executive", "dir"),
    ("reports/agency-ao", "dir"),
    ("evidence/package/reports/assessor", "dir"),
    ("evidence/package/reports/executive", "dir"),
    ("evidence/package/reports/agency-ao", "dir"),
    ("evidence/package_tracker/reports/assessor", "dir"),
    ("evidence/package_tracker/reports/executive", "dir"),
    ("evidence/package_tracker/reports/agency-ao", "dir"),
    # Validation summary so the demo audience can see the safety gates.
    ("validation_run/validation_summary.md", "file"),
    ("validation_run/validation_summary.json", "file"),
    # Tracker-derived artifacts as written by ``validate_everything`` (which
    # places them under ``validation_run/...`` rather than the top-level
    # ``output_tracker/`` and ``evidence/package_tracker/`` paths used by the
    # standalone ``python agent.py tracker-to-20x`` command).
    ("validation_run/tracker_to_20x/tracker_gap_report.md", "file"),
    ("validation_run/tracker_to_20x/auditor_questions.md", "file"),
    ("validation_run/tracker_to_20x/poam.csv", "file"),
    ("validation_run/tracker_to_20x/package_tracker/fedramp20x-package.json", "file"),
    ("validation_run/tracker_to_20x/package_tracker/reports/assessor", "dir"),
    ("validation_run/tracker_to_20x/package_tracker/reports/executive", "dir"),
    ("validation_run/tracker_to_20x/package_tracker/reports/agency-ao", "dir"),
    ("validation_run/agent_run_tracker/agent_run_summary.md", "file"),
    ("validation_run/agent_run_tracker/agent_run_trace.json", "file"),
    # Web explorer sample data — lets a reviewer open the explorer immediately.
    ("web/sample-data", "dir"),
)


# Always-skipped path components (basename match).
ALWAYS_SKIP_BASENAMES: frozenset[str] = frozenset(
    {".git", ".venv", "__pycache__", "node_modules", "reference", "reference_samples"}
)

# Always-skipped path component substrings (so e.g. ``something_raw_aws_dump``
# is filtered without listing every directory).
ALWAYS_SKIP_FILENAMES: frozenset[str] = frozenset(
    {"creds.json", ".env"}
)
ALWAYS_SKIP_FILE_PATTERNS: tuple[str, ...] = (
    ".env.",
    "id_rsa",
)
ALWAYS_SKIP_FILE_SUFFIXES: tuple[str, ...] = (
    ".pem",
    ".key",
    ".pyc",
    ".pyo",
    ".so",
    ".dylib",
)

# Raw-cloud-evidence path hints (matched as substrings of the relative path).
RAW_EVIDENCE_PATH_HINTS: tuple[str, ...] = (
    "evidence/raw/",
    "evidence/cloud_dumps/",
    "evidence/aws-cli/",
    "/raw_evidence/",
    "/cloud_dump/",
    "_raw_aws.",
    ".aws-cli-output.",
)

MAX_FILE_BYTES = 25 * 1024 * 1024  # 25 MB — defensive cap per file


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class IncludedFile:
    arcname: str  # path inside the zip
    source: str  # path relative to source_root (or absolute if outside)
    size: int
    sha256: str
    category: str  # "doc", "report", "package", "validation", "web", "other"


@dataclass
class SkippedEntry:
    path: str
    reason: str


@dataclass
class GateResult:
    name: str
    ran: bool
    rc: int | None = None
    status: str = ""
    details: dict[str, object] = field(default_factory=dict)
    notes: str = ""


@dataclass
class PackageResult:
    zip_path: Path
    manifest_path: Path
    files: list[IncludedFile]
    skipped: list[SkippedEntry]
    gates: dict[str, GateResult]
    source_root: Path
    started_at: str
    completed_at: str
    aborted_reason: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _categorize(rel: str) -> str:
    rel = rel.replace("\\", "/")
    if rel.startswith("docs/") or rel == "README.md":
        return "doc"
    if rel.startswith("reports/") or "/reports/" in rel:
        return "report"
    if rel.startswith("evidence/") and rel.endswith("fedramp20x-package.json"):
        return "package"
    if rel.startswith("evidence/"):
        return "report"  # the report subtrees inside a package
    if rel.startswith("output") or rel.endswith("_summary.md") or rel.endswith("_walkthrough.md"):
        return "summary"
    if rel.startswith("validation_run/"):
        return "validation"
    if rel.startswith("web/sample-data"):
        return "web"
    return "other"


def is_excluded(rel: str, *, allow_raw_evidence: bool) -> tuple[bool, str]:
    """Return (excluded, reason). Reason is "" when the file is included."""
    rel_norm = rel.replace("\\", "/")
    parts = rel_norm.split("/")
    base = parts[-1]
    for component in parts:
        if component in ALWAYS_SKIP_BASENAMES:
            return True, f"path component '{component}' is in always-skip list"
    if base in ALWAYS_SKIP_FILENAMES:
        return True, f"filename '{base}' is in always-skip list"
    for prefix in ALWAYS_SKIP_FILE_PATTERNS:
        if prefix in base:
            return True, f"filename matches always-skip pattern '{prefix}'"
    for suffix in ALWAYS_SKIP_FILE_SUFFIXES:
        if base.endswith(suffix):
            return True, f"filename suffix '{suffix}' is excluded (likely binary or sensitive)"
    if not allow_raw_evidence:
        for hint in RAW_EVIDENCE_PATH_HINTS:
            if hint in rel_norm:
                return True, f"raw cloud evidence path hint '{hint}' (re-run with --allow-raw-evidence to include)"
    return False, ""


def _iter_files_under(root: Path, base: Path) -> Iterable[Path]:
    """Yield every file under ``root`` (recursive). Symlinks are skipped."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune hidden/skip dirs in-place so os.walk doesn't recurse into them.
        dirnames[:] = [d for d in dirnames if d not in ALWAYS_SKIP_BASENAMES]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            yield p


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def run_secret_scan(
    source_root: Path,
    *,
    paths: list[Path] | None = None,
) -> GateResult:
    """Run the secret/PII scanner. FAIL aborts packaging."""
    gate = GateResult(name="scan_generated_outputs", ran=True)
    if not SCAN_SCRIPT.exists():
        gate.ran = False
        gate.notes = f"scanner script not found at {SCAN_SCRIPT}"
        return gate
    cmd = [sys.executable, str(SCAN_SCRIPT), "--json"]
    if paths:
        cmd.extend(["--paths", *[str(p) for p in paths]])
    proc = subprocess.run(
        cmd,
        cwd=source_root,
        capture_output=True,
        text=True,
        timeout=300,
    )
    gate.rc = proc.returncode
    body: dict[str, object] = {}
    try:
        body = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        gate.notes = "scanner produced non-JSON output"
    if body:
        gate.details = {
            "files_scanned": body.get("files_scanned"),
            "paths_scanned": body.get("paths_scanned", []),
            "reportable": len(body.get("reportable", []) or []),
            "allowlisted": len(body.get("allowlisted", []) or []),
            # Include redacted findings so the manifest is auditable.
            "reportable_findings": body.get("reportable", []),
        }
    gate.status = "PASS" if proc.returncode == 0 else "FAIL"
    return gate


def run_validate_everything(
    source_root: Path,
    *,
    tracker: Path,
    output_root: Path,
    skip_pytest: bool,
) -> GateResult:
    """Run end-to-end validation. FAIL aborts; WARN allowed (recorded)."""
    gate = GateResult(name="validate_everything", ran=True)
    if not VALIDATE_SCRIPT.exists():
        gate.ran = False
        gate.notes = f"validate script not found at {VALIDATE_SCRIPT}"
        return gate
    cmd = [
        sys.executable,
        str(VALIDATE_SCRIPT),
        "--tracker",
        str(tracker),
        "--output-root",
        str(output_root),
    ]
    if skip_pytest:
        cmd.append("--skip-pytest")
    proc = subprocess.run(
        cmd,
        cwd=source_root,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    gate.rc = proc.returncode
    summary_json = output_root / "validation_summary.json"
    overall = ""
    if summary_json.exists():
        try:
            body = json.loads(summary_json.read_text(encoding="utf-8"))
            overall = str(body.get("overall_status", "")).upper()
            summary_md_path = output_root / "validation_summary.md"
            try:
                summary_md_str = str(summary_md_path.relative_to(source_root))
            except ValueError:
                summary_md_str = str(summary_md_path)
            gate.details = {
                "overall_status": overall,
                "step_counts": body.get("step_counts", {}),
                "summary_md": summary_md_str,
            }
        except (json.JSONDecodeError, OSError) as e:
            gate.notes = f"failed to parse validation_summary.json: {e}"
    if proc.returncode == 0:
        # rc=0 → WARN or PASS. Use the summary's overall_status if present.
        gate.status = overall or "PASS"
    else:
        gate.status = "FAIL"
    if proc.stderr.strip():
        gate.notes = (gate.notes + "\n" + proc.stderr.strip()[:500]).strip()
    return gate


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def collect_files(
    source_root: Path,
    *,
    allow_raw_evidence: bool,
) -> tuple[list[tuple[Path, str]], list[SkippedEntry]]:
    """Walk the include catalog and return (kept_files, skipped_entries).

    ``kept_files`` items are ``(absolute_path, arcname)`` ready for zipping.
    """
    kept: list[tuple[Path, str]] = []
    skipped: list[SkippedEntry] = []
    seen_arcnames: set[str] = set()

    def _add_file(abs_path: Path, rel: str) -> None:
        rel = rel.replace("\\", "/")
        excluded, reason = is_excluded(rel, allow_raw_evidence=allow_raw_evidence)
        if excluded:
            skipped.append(SkippedEntry(path=rel, reason=reason))
            return
        try:
            size = abs_path.stat().st_size
        except OSError as e:
            skipped.append(SkippedEntry(path=rel, reason=f"stat failed: {e}"))
            return
        if size > MAX_FILE_BYTES:
            skipped.append(SkippedEntry(path=rel, reason=f"file size {size} > MAX_FILE_BYTES"))
            return
        if rel in seen_arcnames:
            return  # already added via a more specific catalog entry
        seen_arcnames.add(rel)
        kept.append((abs_path, rel))

    for entry, kind in DEMO_INCLUDE_LIST:
        candidate = (source_root / entry).resolve()
        # Stay inside the source tree.
        try:
            rel_root = str(candidate.relative_to(source_root.resolve())).replace("\\", "/")
        except ValueError:
            skipped.append(SkippedEntry(path=entry, reason="resolves outside source root"))
            continue
        if not candidate.exists():
            skipped.append(SkippedEntry(path=entry, reason="not present (skipped silently)"))
            continue
        if kind == "file":
            if not candidate.is_file():
                skipped.append(SkippedEntry(path=entry, reason=f"expected file, got {('dir' if candidate.is_dir() else 'other')}"))
                continue
            _add_file(candidate, rel_root)
        elif kind == "dir":
            if not candidate.is_dir():
                skipped.append(SkippedEntry(path=entry, reason=f"expected directory, got {('file' if candidate.is_file() else 'other')}"))
                continue
            for f in _iter_files_under(candidate, source_root.resolve()):
                try:
                    rel = str(f.relative_to(source_root.resolve())).replace("\\", "/")
                except ValueError:
                    continue
                _add_file(f, rel)
    return kept, skipped


def write_zip(
    kept: list[tuple[Path, str]],
    output_zip: Path,
) -> list[IncludedFile]:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    included: list[IncludedFile] = []
    with zipfile.ZipFile(
        output_zip,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for abs_path, arcname in sorted(kept, key=lambda x: x[1]):
            zf.write(abs_path, arcname=arcname)
            included.append(
                IncludedFile(
                    arcname=arcname,
                    source=arcname,
                    size=abs_path.stat().st_size,
                    sha256=_sha256_of(abs_path),
                    category=_categorize(arcname),
                )
            )
    return included


def write_manifest(
    manifest_path: Path,
    result: PackageResult,
) -> None:
    by_category: dict[str, int] = {}
    for f in result.files:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    payload = {
        "schema_version": "1.0",
        "tool": "package_demo_artifacts",
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "source_root": str(result.source_root),
        "zip_path": str(result.zip_path),
        "aborted_reason": result.aborted_reason,
        "totals": {
            "files": len(result.files),
            "bytes": sum(f.size for f in result.files),
            "skipped": len(result.skipped),
            "by_category": by_category,
        },
        "gates": {
            name: {
                "ran": g.ran,
                "rc": g.rc,
                "status": g.status,
                "details": g.details,
                "notes": g.notes,
            }
            for name, g in result.gates.items()
        },
        "files": [
            {
                "arcname": f.arcname,
                "size": f.size,
                "sha256": f.sha256,
                "category": f.category,
            }
            for f in result.files
        ],
        "skipped": [{"path": s.path, "reason": s.reason} for s in result.skipped],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def package(
    source_root: Path,
    output_zip: Path,
    *,
    manifest_path: Path | None = None,
    allow_raw_evidence: bool = False,
    skip_scan: bool = False,
    skip_validation: bool = False,
    tracker: Path | None = None,
    validation_output_root: Path | None = None,
    validation_skip_pytest: bool = True,
) -> PackageResult:
    started = _now_iso()
    source_root = source_root.resolve()
    output_zip = output_zip.resolve()
    manifest_path = (manifest_path or output_zip.with_name("demo_artifacts_manifest.json")).resolve()

    gates: dict[str, GateResult] = {}

    # ---- Gate 1: secret scan ------------------------------------------------
    if not skip_scan:
        gate = run_secret_scan(source_root)
        gates["scan_generated_outputs"] = gate
        if gate.status == "FAIL":
            result = PackageResult(
                zip_path=output_zip,
                manifest_path=manifest_path,
                files=[],
                skipped=[],
                gates=gates,
                source_root=source_root,
                started_at=started,
                completed_at=_now_iso(),
                aborted_reason="secret scan reported one or more findings; refusing to package",
            )
            write_manifest(manifest_path, result)
            return result
    else:
        gates["scan_generated_outputs"] = GateResult(
            name="scan_generated_outputs",
            ran=False,
            notes="explicitly skipped by --skip-scan",
        )

    # ---- Gate 2: validate_everything ---------------------------------------
    if not skip_validation:
        if tracker is None:
            tracker = source_root / "fixtures" / "assessment_tracker" / "sample_tracker.csv"
        if validation_output_root is None:
            validation_output_root = source_root / "validation_run"
        gate = run_validate_everything(
            source_root,
            tracker=tracker,
            output_root=validation_output_root,
            skip_pytest=validation_skip_pytest,
        )
        gates["validate_everything"] = gate
        if gate.status == "FAIL":
            result = PackageResult(
                zip_path=output_zip,
                manifest_path=manifest_path,
                files=[],
                skipped=[],
                gates=gates,
                source_root=source_root,
                started_at=started,
                completed_at=_now_iso(),
                aborted_reason="validate_everything FAILED; refusing to package",
            )
            write_manifest(manifest_path, result)
            return result
    else:
        gates["validate_everything"] = GateResult(
            name="validate_everything",
            ran=False,
            notes="explicitly skipped by --skip-validation",
        )

    # ---- Collect + zip ------------------------------------------------------
    kept, skipped = collect_files(source_root, allow_raw_evidence=allow_raw_evidence)

    # Defensive secondary scan: a curated artifact may live OUTSIDE the
    # canonical scanner-watched directories (e.g. the README at the repo root).
    # Reuse the catalog from scan_generated_outputs to detect any secret-shaped
    # value in the files we are about to include and abort if any reportable
    # match remains. This is the contract acceptance test asks for: "no
    # secrets included".
    try:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import scan_generated_outputs as _scanner
    finally:
        try:
            sys.path.remove(str(REPO_ROOT / "scripts"))
        except ValueError:
            pass
    secondary_findings: list[dict[str, object]] = []
    live_findings: list[dict[str, object]] = []
    for abs_path, arc in kept:
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for f in _scanner.scan_text(text, file_label=arc, scan_emails=False):
            if not f.allowlisted:
                secondary_findings.append(
                    {
                        "file": f.file,
                        "line": f.line,
                        "column": f.column,
                        "category": f.category,
                        "preview": f.preview,
                    }
                )
    try:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import guard_live_artifacts as _live_guard
    finally:
        try:
            sys.path.remove(str(REPO_ROOT / "scripts"))
        except ValueError:
            pass
    live_guard_findings = _live_guard.scan_paths(
        [p for p, _arc in kept],
        allowed_accounts=set(_live_guard.DEFAULT_ALLOWED_ACCOUNTS),
        base=source_root,
    )
    live_findings = [f.to_dict() for f in live_guard_findings]
    gates["pre_zip_secret_scan"] = GateResult(
        name="pre_zip_secret_scan",
        ran=True,
        rc=0 if not secondary_findings else 1,
        status="PASS" if not secondary_findings else "FAIL",
        details={"reportable_findings": secondary_findings},
    )
    gates["pre_zip_live_artifact_guard"] = GateResult(
        name="pre_zip_live_artifact_guard",
        ran=True,
        rc=0 if not live_findings else 1,
        status="PASS" if not live_findings else "FAIL",
        details={"reportable_findings": live_findings},
    )
    if secondary_findings or live_findings:
        result = PackageResult(
            zip_path=output_zip,
            manifest_path=manifest_path,
            files=[],
            skipped=skipped,
            gates=gates,
            source_root=source_root,
            started_at=started,
            completed_at=_now_iso(),
            aborted_reason=(
                f"{len(secondary_findings)} secret-shaped value(s) and {len(live_findings)} live cloud "
                "identifier(s) detected in curated files; refusing to package. See pre_zip_* gates in "
                "manifest for redacted details."
            ),
        )
        write_manifest(manifest_path, result)
        return result

    included = write_zip(kept, output_zip)

    result = PackageResult(
        zip_path=output_zip,
        manifest_path=manifest_path,
        files=included,
        skipped=skipped,
        gates=gates,
        source_root=source_root,
        started_at=started,
        completed_at=_now_iso(),
    )
    write_manifest(manifest_path, result)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Package demo-ready artifacts into a zip + manifest.",
    )
    p.add_argument("--source-root", type=Path, default=Path("."), help="Repo root (default: cwd).")
    p.add_argument("--output", type=Path, default=Path("demo_artifacts.zip"), help="Output zip path.")
    p.add_argument("--manifest", type=Path, default=None, help="Manifest path (default: <output>_manifest.json next to zip).")
    p.add_argument(
        "--allow-raw-evidence",
        action="store_true",
        help="Include raw cloud evidence dumps. Off by default.",
    )
    p.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip the pre-package secret scan (NOT recommended for shareable bundles).",
    )
    p.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip the pre-package run of scripts/validate_everything.py.",
    )
    p.add_argument(
        "--tracker",
        type=Path,
        default=None,
        help="Tracker file passed to validate_everything (default: fixtures/assessment_tracker/sample_tracker.csv).",
    )
    p.add_argument(
        "--validation-output-root",
        type=Path,
        default=None,
        help="Output root for validate_everything (default: <source-root>/validation_run).",
    )
    p.add_argument(
        "--validation-include-pytest",
        action="store_true",
        help="Include pytest in validate_everything (default: --skip-pytest is passed).",
    )
    return p.parse_args(argv)


def _print_summary(result: PackageResult) -> None:
    if result.aborted_reason:
        print(f"package_demo_artifacts: ABORTED — {result.aborted_reason}", file=sys.stderr)
        print(f"  manifest : {result.manifest_path}", file=sys.stderr)
        return
    by_cat: dict[str, int] = {}
    for f in result.files:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    print(f"package_demo_artifacts: wrote {result.zip_path}")
    print(f"  manifest : {result.manifest_path}")
    print(f"  files    : {len(result.files)}  ({', '.join(f'{k}={v}' for k, v in sorted(by_cat.items()))})")
    print(f"  skipped  : {len(result.skipped)} entry/entries")
    for name, g in result.gates.items():
        marker = {"PASS": "✓", "WARN": "!", "FAIL": "✗", "": "·"}.get(g.status, "·")
        suffix = ""
        if name == "scan_generated_outputs" and g.details:
            suffix = (
                f" — files={g.details.get('files_scanned')} "
                f"reportable={g.details.get('reportable')} allowlisted={g.details.get('allowlisted')}"
            )
        elif name == "validate_everything" and g.details:
            counts = g.details.get("step_counts", {})
            suffix = f" — overall={g.details.get('overall_status')} {dict(counts)}"
        print(f"  gate     : {marker} {name:30} {g.status or 'SKIP':5}{suffix}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_root = args.source_root.resolve()
    if not source_root.is_dir():
        print(f"error: --source-root {source_root} is not a directory", file=sys.stderr)
        return 2
    output_zip = (args.output if args.output.is_absolute() else source_root / args.output).resolve()
    manifest_path = (
        (args.manifest if args.manifest and args.manifest.is_absolute() else (source_root / args.manifest if args.manifest else None))
        or output_zip.with_name("demo_artifacts_manifest.json")
    )

    result = package(
        source_root=source_root,
        output_zip=output_zip,
        manifest_path=manifest_path,
        allow_raw_evidence=args.allow_raw_evidence,
        skip_scan=args.skip_scan,
        skip_validation=args.skip_validation,
        tracker=args.tracker,
        validation_output_root=args.validation_output_root,
        validation_skip_pytest=not args.validation_include_pytest,
    )
    _print_summary(result)
    return 0 if result.aborted_reason is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
