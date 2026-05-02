"""Reference samples are documentation-only and must not drift from manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RS = ROOT / "reference_samples"
MANIFEST = RS / "manifest.json"


def test_manifest_exists_and_lists_all_copied_files() -> None:
    assert MANIFEST.is_file()
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    paths = {e["copied_path"] for e in data["files"]}
    missing = []
    for rel in sorted(paths):
        if not (ROOT / rel).is_file():
            missing.append(rel)
    assert not missing, f"Manifest lists missing files: {missing}"


def test_manifest_entry_count_matches_reference_samples_files() -> None:
    """Every tracked file under reference_samples/ (except README) appears in manifest."""
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest_paths = {e["copied_path"] for e in data["files"]}
    on_disk = {
        str(p.relative_to(ROOT)).replace("\\", "/")
        for p in RS.rglob("*")
        if p.is_file() and p.name not in ("README.md", "manifest.json")
    }
    assert manifest_paths == on_disk


@pytest.mark.parametrize(
    "pkg",
    ["core", "evals", "providers", "instrumentation", "agent.py"],
)
def test_runtime_packages_do_not_reference_samples_path(pkg: str) -> None:
    """Acceptance: no runtime code imports or reads reference_samples."""
    needle = "reference_samples"
    if pkg.endswith(".py"):
        paths = [ROOT / pkg]
    else:
        paths = list((ROOT / pkg).rglob("*.py"))
    hits = []
    for path in paths:
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if needle in text:
            hits.append(str(path.relative_to(ROOT)))
    assert not hits, f"reference_samples mentioned in: {hits}"
