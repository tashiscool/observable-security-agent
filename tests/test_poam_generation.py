from __future__ import annotations

from pathlib import Path

from core.evaluator import run_evaluations
from core.normalizer import load_normalized_primary_event
from core.poam import poam_rows_from_bundle
from providers.fixture import FixtureProvider


def test_demo_scenario_generates_poam_rows() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"
    bundle = FixtureProvider(root).load()
    sem, _ = load_normalized_primary_event(bundle)
    cb = run_evaluations(bundle, sem)
    rows = poam_rows_from_bundle(cb)
    assert len(rows) >= 1
