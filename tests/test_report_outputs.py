from __future__ import annotations

import json
from pathlib import Path

from core.evaluator import run_evaluations
from core.normalizer import load_normalized_primary_event
from core.report_writer import correlation_bundle_from_eval_results, eval_results_to_json_serializable
from providers.fixture import FixtureProvider


def test_eval_results_round_trip() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"
    bundle = FixtureProvider(root).load()
    sem, _ = load_normalized_primary_event(bundle)
    cb = run_evaluations(bundle, sem)
    payload = eval_results_to_json_serializable(cb)
    loaded = correlation_bundle_from_eval_results(payload)
    assert loaded.correlation_id == cb.correlation_id
    assert len(loaded.eval_results) == len(cb.eval_results)
    assert json.loads(json.dumps(payload))["schema_version"] == "1.2"
    assert len(payload["eval_result_records"]) == len(payload["evaluations"])
