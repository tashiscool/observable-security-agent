#!/usr/bin/env python3
"""Audit reference-sample layout, licenses, and runtime boundaries.

Writes ``validation_run/reference_reuse_audit.md`` and exits 0 only if all checks pass.

Rules (summary):
  * Tracked files under ``reference_samples/`` must appear in ``manifest.json`` (and vice versa).
  * License files under ``reference_samples/licenses/`` must be listed in the manifest and exist.
  * Unknown / unset ``source_license`` requires ``direct_code_reuse_allowed`` to be false or unknown.
  * Runtime Python (same roots as ``validate_everything`` plus ``instrumentation``) must not import
    ``reference_samples`` or ``reference.*``. ``tests/`` are not scanned for this rule.
  * Source-like manifest paths must live only under ``reference_samples/``.
  * Runtime code trees must not contain a file with the same name and *identical content* as a
    source-like excerpt under ``reference_samples/`` (flags verbatim copies into product code).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Runtime package roots scanned for forbidden imports (``tests/`` excluded by design).
_RUNTIME_IMPORT_ROOTS: tuple[str, ...] = (
    "agent.py",
    "agent_loop",
    "ai",
    "api",
    "classification",
    "core",
    "evals",
    "fedramp20x",
    "instrumentation",
    "normalization",
    "providers",
    "scripts",
)

# Dirs checked for duplicate *content* vs reference_samples source-like files.
_RUNTIME_DUP_CHECK_ROOTS: tuple[str, ...] = (
    "core",
    "providers",
    "normalization",
    "fedramp20x",
    "agent_loop",
    "ai",
    "api",
    "classification",
    "evals",
    "instrumentation",
)

_REF_IMPORT_RE = re.compile(
    r"^\s*("
    r"from\s+reference_samples(?:\.[A-Za-z_][\w]*)*\s+import\s+"
    r"|import\s+reference_samples(?:\.[A-Za-z_][\w]*)*"
    r"|from\s+reference(?:\.[A-Za-z_][\w]*)*\s+import\s+"
    r"|import\s+reference(?:\.[A-Za-z_][\w]*)+"
    r")",
    re.MULTILINE,
)

# Executable / compilable-style artifacts (not docs-only).
_SOURCE_LIKE_SUFFIXES: tuple[str, ...] = (
    ".py",
    ".js",
    ".go",
    ".rs",
    ".java",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
)

_SKIP_DUP_BASENAMES: frozenset[str] = frozenset({"__init__.py"})

_MIN_DUP_BYTES = 64


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _runtime_python_files(repo: Path) -> list[Path]:
    out: list[Path] = []
    for entry in _RUNTIME_IMPORT_ROOTS:
        target = repo / entry
        if target.is_file() and target.suffix == ".py":
            out.append(target)
        elif target.is_dir():
            for p in target.rglob("*.py"):
                if "__pycache__" in p.parts:
                    continue
                out.append(p)
    return out


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _is_source_like_path(copied_path: str) -> bool:
    lower = copied_path.lower()
    if lower.endswith(".py.txt"):
        return True
    return lower.endswith(_SOURCE_LIKE_SUFFIXES)


def _license_unknown(raw: Any) -> bool:
    if raw is None:
        return True
    t = str(raw).strip().lower()
    if not t:
        return True
    if t in ("unknown", "unspecified", "n/a", "n/a.", "see upstream", "see notes", "tbd"):
        return True
    if "confirm" in t and "license" in t:
        return True
    return False


def _reuse_explicitly_true(raw: Any) -> bool:
    if raw is True:
        return True
    if isinstance(raw, str) and raw.strip().lower() == "true":
        return True
    return False


def _reuse_false_or_unknown_or_absent(raw: Any) -> bool:
    if raw is None or raw is False:
        return True
    if isinstance(raw, str):
        s = raw.strip().lower()
        return s in ("false", "unknown", "")
    return False


def run_audit(repo: Path) -> tuple[bool, str]:
    lines: list[str] = []
    failures: list[str] = []

    def add(title: str, body: str) -> None:
        lines.append(f"## {title}\n")
        lines.append(body.rstrip() + "\n\n")

    utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append("# Reference reuse audit\n\n")
    lines.append(f"Generated: `{utc}` (UTC)  \n")
    lines.append(f"Repository root: `{repo}`\n\n")

    rs_dir = repo / "reference_samples"
    manifest_path = rs_dir / "manifest.json"
    if not manifest_path.is_file():
        msg = f"Missing `reference_samples/manifest.json` at `{manifest_path}`"
        failures.append(msg)
        add("Manifest", f"**FAIL** — {msg}")
        report = "".join(lines)
        return False, report

    data = _load_manifest(manifest_path)
    file_entries = data.get("files")
    if not isinstance(file_entries, list):
        failures.append("manifest `files` must be a JSON array")
        file_entries = []

    manifest_paths = {str(e.get("copied_path", "")).replace("\\", "/") for e in file_entries if isinstance(e, dict)}
    manifest_paths.discard("")

    # --- On-disk vs manifest ---
    on_disk: set[str] = set()
    if rs_dir.is_dir():
        on_disk = {
            str(p.relative_to(repo)).replace("\\", "/")
            for p in rs_dir.rglob("*")
            if p.is_file() and p.name not in ("README.md", "manifest.json")
        }
    missing_in_manifest = sorted(on_disk - manifest_paths)
    missing_on_disk = sorted(manifest_paths - on_disk)
    if missing_in_manifest:
        failures.append(f"{len(missing_in_manifest)} on-disk reference_samples file(s) not in manifest")
    if missing_on_disk:
        failures.append(f"{len(missing_on_disk)} manifest copied_path(s) missing on disk")

    body = "Tracked files under `reference_samples/` must match `manifest.json` `files[].copied_path`.\n\n"
    if not missing_in_manifest and not missing_on_disk:
        body += f"- **PASS** — {len(on_disk)} files mirrored in manifest.\n"
    else:
        if missing_in_manifest:
            body += "- **FAIL** — not in manifest (sample):\n"
            for p in missing_in_manifest[:30]:
                body += f"  - `{p}`\n"
            if len(missing_in_manifest) > 30:
                body += f"  - … and {len(missing_in_manifest) - 30} more\n"
        if missing_on_disk:
            body += "- **FAIL** — manifest lists missing files (sample):\n"
            for p in missing_on_disk[:30]:
                body += f"  - `{p}`\n"
            if len(missing_on_disk) > 30:
                body += f"  - … and {len(missing_on_disk) - 30} more\n"
    add("Copied files ↔ manifest", body)

    # --- License files ---
    lic_dir = rs_dir / "licenses"
    lic_on_disk: set[str] = set()
    if lic_dir.is_dir():
        lic_on_disk = {
            str(p.relative_to(repo)).replace("\\", "/") for p in lic_dir.iterdir() if p.is_file()
        }
    lic_in_manifest = {p for p in manifest_paths if p.startswith("reference_samples/licenses/")}
    orphan_lic = sorted(lic_on_disk - manifest_paths)
    missing_lic_disk = sorted(lic_in_manifest - on_disk)
    if orphan_lic:
        failures.append(f"{len(orphan_lic)} license file(s) on disk not listed in manifest")
    if missing_lic_disk:
        failures.append(f"{len(missing_lic_disk)} manifest license path(s) missing on disk")

    lic_body = (
        "Every file in `reference_samples/licenses/` must appear in `manifest.json`. "
        "Every manifest path under that directory must exist.\n\n"
    )
    if not orphan_lic and not missing_lic_disk:
        lic_body += f"- **PASS** — {len(lic_on_disk)} license file(s) consistent.\n"
    else:
        if orphan_lic:
            lic_body += "- **FAIL** — on disk but not in manifest:\n"
            for p in orphan_lic:
                lic_body += f"  - `{p}`\n"
        if missing_lic_disk:
            lic_body += "- **FAIL** — in manifest but missing on disk:\n"
            for p in missing_lic_disk:
                lic_body += f"  - `{p}`\n"
    add("License file inventory", lic_body)

    # --- Unknown license vs direct_code_reuse_allowed ---
    lic_rule_body = (
        "If `source_license` is unknown or empty, `direct_code_reuse_allowed` must be "
        "`false`, `unknown`, absent, or boolean false — never `true`.\n\n"
    )
    bad_lic: list[str] = []
    for i, e in enumerate(file_entries):
        if not isinstance(e, dict):
            continue
        sl = e.get("source_license")
        reuse = e.get("direct_code_reuse_allowed")
        if _license_unknown(sl) and _reuse_explicitly_true(reuse):
            cp = e.get("copied_path", "?")
            bad_lic.append(f"files[{i}] `{cp}`: unknown license but direct_code_reuse_allowed=true")
        if _license_unknown(sl) and not _reuse_false_or_unknown_or_absent(reuse) and not _reuse_explicitly_true(reuse):
            # e.g. string "maybe" — treat as failure
            cp = e.get("copied_path", "?")
            bad_lic.append(
                f"files[{i}] `{cp}`: unknown license but direct_code_reuse_allowed={reuse!r} "
                "(must be false or unknown)"
            )
    if bad_lic:
        failures.extend(bad_lic)
        lic_rule_body += "- **FAIL**:\n"
        for row in bad_lic:
            lic_rule_body += f"  - {row}\n"
    else:
        lic_rule_body += "- **PASS** — no unknown-license row allows copy-by-default.\n"
    add("Unknown license vs reuse flag", lic_rule_body)

    # --- Source-like paths only under reference_samples ---
    src_body = (
        "Manifest entries whose `copied_path` ends with a source-like suffix "
        f"(`{', '.join(_SOURCE_LIKE_SUFFIXES)}`, plus `.py.txt` excerpts) "
        "must use `reference_samples/...`.\n\n"
    )
    bad_paths: list[str] = []
    for e in file_entries:
        if not isinstance(e, dict):
            continue
        cp = str(e.get("copied_path") or "")
        if _is_source_like_path(cp) and not cp.startswith("reference_samples/"):
            bad_paths.append(cp)
    if bad_paths:
        failures.append(f"{len(bad_paths)} source-like manifest path(s) outside reference_samples/")
        src_body += "- **FAIL**:\n"
        for p in bad_paths:
            src_body += f"  - `{p}`\n"
    else:
        src_body += "- **PASS** — all source-like excerpts are under `reference_samples/`.\n"
    add("Source-like paths stay under reference_samples/", src_body)

    # --- Verbatim duplicate of reference source into runtime trees ---
    dup_body = (
        "If a source-like file under `reference_samples/` has the same basename and **identical "
        "bytes** as a file under product code roots, that is flagged (verbatim vendoring).\n\n"
    )
    duplicates: list[str] = []
    ref_source_files: list[Path] = []
    for e in file_entries:
        if not isinstance(e, dict):
            continue
        cp = str(e.get("copied_path") or "")
        if not _is_source_like_path(cp):
            continue
        refp = repo / cp
        if not refp.is_file():
            continue
        if refp.stat().st_size < _MIN_DUP_BYTES:
            continue
        if refp.name in _SKIP_DUP_BASENAMES:
            continue
        ref_source_files.append(refp)

    for refp in ref_source_files:
        data_b = refp.read_bytes()
        name = refp.name
        for root_name in _RUNTIME_DUP_CHECK_ROOTS:
            base = repo / root_name
            if not base.is_dir():
                continue
            for candidate in base.rglob(name):
                if not candidate.is_file():
                    continue
                if candidate.resolve() == refp.resolve():
                    continue
                try:
                    if candidate.stat().st_size != len(data_b):
                        continue
                    if candidate.read_bytes() == data_b:
                        duplicates.append(
                            f"`{_safe_rel(refp, repo)}` == `{_safe_rel(candidate, repo)}` "
                            f"({len(data_b)} bytes)"
                        )
                except OSError:
                    continue

    if duplicates:
        failures.extend(duplicates)
        dup_body += "- **FAIL** — identical content found:\n"
        for row in duplicates[:40]:
            dup_body += f"  - {row}\n"
        if len(duplicates) > 40:
            dup_body += f"  - … and {len(duplicates) - 40} more\n"
    else:
        dup_body += (
            f"- **PASS** — checked {len(ref_source_files)} source-like reference file(s); "
            "no byte-identical copies under runtime roots.\n"
        )
    add("No verbatim source copies in runtime trees", dup_body)

    # --- Runtime import audit (tests excluded) ---
    imp_lines: list[str] = []
    offenders: list[str] = []
    for p in _runtime_python_files(repo):
        rel = _safe_rel(p, repo)
        if rel.startswith("tests/"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in _REF_IMPORT_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{rel}:{line_no}: {match.group(0).strip()}")

    imp_lines.append(
        "Scanned Python under: "
        + ", ".join( f"`{x}`" for x in _RUNTIME_IMPORT_ROOTS)
        + " (excluding `tests/`).\n\n"
    )
    if offenders:
        failures.extend(offenders)
        imp_lines.append(f"- **FAIL** — {len(offenders)} forbidden import line(s):\n")
        for o in offenders[:50]:
            imp_lines.append(f"  - `{o}`\n")
        if len(offenders) > 50:
            imp_lines.append(f"  - … and {len(offenders) - 50} more\n")
    else:
        imp_lines.append(
            "- **PASS** — no `import reference_samples` / `import reference.*` in runtime code.\n"
        )
    imp_lines.append(
        "\n*(Tests may read `reference_samples/` paths; this scan intentionally ignores `tests/`.)*\n"
    )
    add("Runtime import boundary", "".join(imp_lines))

    # --- Summary ---
    ok = not failures
    summ = "## Summary\n\n"
    if ok:
        summ += "**Result: PASS** — reference reuse rules satisfied.\n\n"
    else:
        summ += f"**Result: FAIL** — {len(failures)} issue(s).\n\n"
    # Insert summary after title + generated timestamp + repo root (indices 0..2).
    lines.insert(3, summ)

    return ok, "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (default: parent of scripts/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Markdown report path (default: <repo>/validation_run/reference_reuse_audit.md)",
    )
    args = parser.parse_args()
    repo = (args.repo_root or _repo_root()).resolve()
    out = (args.output or (repo / "validation_run" / "reference_reuse_audit.md")).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    ok, report = run_audit(repo)
    out.write_text(report, encoding="utf-8")
    print(f"Wrote {out} ({'PASS' if ok else 'FAIL'})")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
