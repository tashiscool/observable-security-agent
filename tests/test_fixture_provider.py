from __future__ import annotations

from pathlib import Path

from core.utils import validate_evidence_bundle_minimum
from providers.fixture import FixtureProvider


def test_fixture_provider_loads_demo_scenario() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"
    p = FixtureProvider(root)
    bundle = p.load()
    validate_evidence_bundle_minimum(bundle)
    assert bundle.source_root == root.resolve()
    assert len(bundle.declared_inventory_rows) >= 5
