"""KSI catalog YAML models and loaders."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fedramp20x.ksi_catalog import KsiCatalogLoadError, load_ksi_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "config" / "ksi-catalog.yaml"


def test_catalog_loads() -> None:
    cat = load_ksi_catalog(CATALOG_PATH)
    assert cat.schema_version == "1.0"
    assert len(cat.catalog) == 12
    ids = [k.ksi_id for k in cat.catalog]
    assert "KSI-IAM-01" in ids
    assert "KSI-LOG-01" in ids


def test_all_ksi_ids_unique() -> None:
    cat = load_ksi_catalog(CATALOG_PATH)
    ids = [k.ksi_id for k in cat.catalog]
    assert len(ids) == len(set(ids))


def test_every_ksi_has_criteria() -> None:
    cat = load_ksi_catalog(CATALOG_PATH)
    for k in cat.catalog:
        assert k.pass_fail_criteria, f"{k.ksi_id} missing criteria"


def test_every_ksi_maps_to_legacy_controls() -> None:
    cat = load_ksi_catalog(CATALOG_PATH)
    for k in cat.catalog:
        assert k.legacy_controls.rev4 or k.legacy_controls.rev5, k.ksi_id


def test_invalid_yaml_fails_clearly(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("{ not: valid yaml [[[", encoding="utf-8")
    with pytest.raises(KsiCatalogLoadError) as ei:
        load_ksi_catalog(p)
    assert "YAML" in str(ei.value) or "yaml" in str(ei.value).lower()


def test_duplicate_ksi_id_fails(tmp_path: Path) -> None:
    p = tmp_path / "dup.yaml"
    doc = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    doc["catalog"].append(doc["catalog"][0])
    p.write_text(yaml.dump(doc), encoding="utf-8")
    with pytest.raises(KsiCatalogLoadError) as ei:
        load_ksi_catalog(p)
    assert "Duplicate" in str(ei.value) or "duplicate" in str(ei.value).lower()


def test_missing_criteria_fails(tmp_path: Path) -> None:
    p = tmp_path / "nocrit.yaml"
    doc = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    doc["catalog"][0]["pass_fail_criteria"] = []
    p.write_text(yaml.dump(doc), encoding="utf-8")
    with pytest.raises(KsiCatalogLoadError):
        load_ksi_catalog(p)
