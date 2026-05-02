"""Manifest completeness, required fields, and runtime import boundaries for ``reference_samples/``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RS = ROOT / "reference_samples"
MANIFEST = RS / "manifest.json"

_MANIFEST_REQUIRED_KEYS = (
    "source_project",
    "original_path",
    "copied_path",
    "reason_copied",
    "category",
)


def _load_validate_everything():
    """Reuse the same scanner as ``step_reference_reuse_audit``."""
    from tests.test_validate_everything import _load_module

    return _load_module()


def test_manifest_exists_lists_every_on_disk_file() -> None:
    assert MANIFEST.is_file(), "reference_samples/manifest.json missing"
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest_paths = {e["copied_path"] for e in data["files"]}
    on_disk = {
        str(p.relative_to(ROOT)).replace("\\", "/")
        for p in RS.rglob("*")
        if p.is_file() and p.name not in ("README.md", "manifest.json")
    }
    missing_on_disk = sorted(manifest_paths - on_disk)
    extra_on_disk = sorted(on_disk - manifest_paths)
    assert not missing_on_disk, f"Manifest lists files not on disk: {missing_on_disk}"
    assert not extra_on_disk, f"On-disk reference_samples files missing from manifest: {extra_on_disk}"


def test_manifest_copied_paths_exist() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    missing = []
    for e in data["files"]:
        rel = e["copied_path"]
        if not (ROOT / rel).is_file():
            missing.append(rel)
    assert not missing, f"manifest copied_path targets missing: {missing}"


@pytest.mark.parametrize("key", _MANIFEST_REQUIRED_KEYS)
def test_manifest_entries_have_required_string_fields(key: str) -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad: list[str] = []
    for i, e in enumerate(data["files"]):
        val = e.get(key)
        if not isinstance(val, str) or not val.strip():
            bad.append(f"files[{i}].{key}={val!r}")
    assert not bad, "Invalid manifest entries:\n" + "\n".join(bad[:25])


def test_runtime_tree_does_not_import_reference_samples() -> None:
    mod = _load_validate_everything()
    offenders: list[str] = []
    for path in mod._python_files(ROOT):
        text = path.read_text(encoding="utf-8")
        for match in mod._REF_IMPORT_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            rel = path.relative_to(ROOT)
            offenders.append(f"{rel}:{line_no}: {match.group(0).strip()}")
    assert not offenders, "Forbidden reference_samples/reference imports:\n" + "\n".join(offenders)
