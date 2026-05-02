"""Tests for :class:`CloudProviderAdapter` / :class:`FixtureProvider` canonical loading."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from providers.fixture import FixtureParseError, FixtureProvider, parse_bool


@pytest.fixture
def scenario_root() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"


def test_parse_bool_csv_variants() -> None:
    assert parse_bool("TRUE") is True
    assert parse_bool("false") is False
    assert parse_bool("") is False
    assert parse_bool(True) is True


def test_fixture_load_bundle_full_scenario_counts(scenario_root: Path) -> None:
    p = FixtureProvider(scenario_root)
    b = p.load_bundle()
    assert len(b.declared_inventory) == 6
    assert len(b.assets) == 5
    assert len(b.events) == 7
    assert len(b.scanner_targets) == 3
    assert len(b.scanner_findings) == 3
    assert len(b.log_sources) == 4
    assert len(b.alert_rules) == 4
    assert len(b.tickets) == 3
    assert len(b.poam_items) == 2
    assert p.provider_name() == "fixture"
    assert p.list_assets() == b.assets
    assert p.list_events() == b.events


def test_all_files_parsed_primary_event_semantics(scenario_root: Path) -> None:
    p = FixtureProvider(scenario_root)
    events = p.list_events()
    primary = next(e for e in events if e.semantic_type == "network.public_admin_port_opened")
    assert primary.asset_id == "prod-api-01"
    assert primary.port == 22
    unknowns = [e for e in events if e.semantic_type == "unknown"]
    assert len(unknowns) == 3


def test_missing_required_file_raises_clear_error(tmp_path: Path, scenario_root: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text(
        "inventory_id,asset_id,name,asset_type,in_boundary,scanner_required,log_required\nx,a,n,c,true,true,true\n",
        encoding="utf-8",
    )
    p = FixtureProvider(tmp_path)
    with pytest.raises(FileNotFoundError) as ei:
        p.load_bundle()
    msg = str(ei.value).lower()
    assert "missing" in msg
    assert "cloud_events.json" in msg or "required" in msg


def test_malformed_declared_csv_raises_fixture_parse_error(tmp_path: Path, scenario_root: Path) -> None:
    for name in FixtureProvider.REQUIRED:
        src = scenario_root / name
        dst = tmp_path / name
        if src.is_file():
            shutil.copyfile(src, dst)
    (tmp_path / "declared_inventory.csv").write_bytes(b"\xff\xfebroken")
    p = FixtureProvider(tmp_path)
    with pytest.raises(FixtureParseError) as ei:
        p.load_bundle()
    msg = str(ei.value).lower()
    assert "csv" in msg or "malformed" in msg or "decode" in msg or "utf-8" in msg


def test_malformed_json_raises_fixture_parse_error(tmp_path: Path, scenario_root: Path) -> None:
    for name in FixtureProvider.REQUIRED:
        src = scenario_root / name
        dst = tmp_path / name
        if src.is_file():
            shutil.copyfile(src, dst)
    (tmp_path / "discovered_assets.json").write_text("{not json", encoding="utf-8")
    p = FixtureProvider(tmp_path)
    with pytest.raises(FixtureParseError) as ei:
        p.load_bundle()
    assert "json" in str(ei.value).lower()


def test_load_pipeline_still_works(scenario_root: Path) -> None:
    p = FixtureProvider(scenario_root)
    pb = p.load()
    assert pb.cloud_events
    b2 = p.load_bundle()
    n_assets = len(json.loads((scenario_root / "discovered_assets.json").read_text(encoding="utf-8"))["assets"])
    assert len(b2.assets) == n_assets
