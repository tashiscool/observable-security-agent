"""Static checks for the Tracker → 20x web explorer.

Verifies:

* the six new nav entries / panels are wired into ``web/index.html``;
* ``web/tracker.js`` exists and registers ``window.OSATracker.bootstrap`` plus
  the LLM reasoner buttons it needs;
* ``web/sample-data/tracker/`` ships a complete fallback so the page still
  renders without ``output_agent_run/`` or ``output_tracker/`` present;
* the FastAPI server exposes ``/api/ai/status`` and ``/api/ai/reasoner`` (which
  the LLM Reasoning tab calls).

These are static / fixture-only assertions — no live LLM is required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
SAMPLE = WEB / "sample-data" / "tracker"

NEW_PANEL_IDS = (
    "tracker-import",
    "tracker-gaps",
    "tracker-trace",
    "tracker-llm",
    "tracker-package",
    "tracker-derivation",
)


# ---------------------------------------------------------------------------
# index.html — new navigation + panels
# ---------------------------------------------------------------------------


def test_index_html_has_all_six_tracker_nav_entries() -> None:
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for pid in NEW_PANEL_IDS:
        # Nav link uses data-panel="<id>".
        assert f'data-panel="{pid}"' in html, f"missing nav entry for {pid}"
        # Each panel must exist as a section.
        assert f'id="panel-{pid}"' in html, f"missing panel section for {pid}"


def test_index_html_loads_tracker_js() -> None:
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert '<script src="tracker.js"></script>' in html
    # Order matters: tracker.js needs to register window.OSATracker BEFORE
    # app.js's boot() runs.
    fedramp_idx = html.find("fedramp20x.js")
    tracker_idx = html.find("tracker.js")
    app_idx = html.find('src="app.js"')
    assert -1 < fedramp_idx < tracker_idx < app_idx


# ---------------------------------------------------------------------------
# tracker.js — required hooks for each tab
# ---------------------------------------------------------------------------


def test_tracker_js_registers_namespace_and_artifact_search_paths() -> None:
    js = (WEB / "tracker.js").read_text(encoding="utf-8")
    # Public namespace exported.
    assert "window.OSATracker" in js
    assert "bootstrap" in js
    # Three artifact search prefixes (output_agent_run → output_tracker → sample-data).
    assert "../output_agent_run/" in js
    assert "../output_tracker/" in js
    assert "sample-data/tracker/" in js
    # Package search includes evidence/package_tracker as well.
    assert "../evidence/package_tracker/" in js


def test_tracker_js_loads_each_required_artifact() -> None:
    js = (WEB / "tracker.js").read_text(encoding="utf-8")
    for name in (
        "scenario_from_tracker/tracker_items.json",
        "scenario_from_tracker/evidence_gaps.json",
        "agent_run_trace.json",
        "agent_run_summary.md",
        "tracker_gap_eval_results.json",
        "fedramp20x-package.json",
        "poam.csv",
        "tracker_poam.csv",
    ):
        assert name in js, f"tracker.js does not reference {name}"


def test_tracker_js_renders_every_required_section() -> None:
    js = (WEB / "tracker.js").read_text(encoding="utf-8")
    # Six render entry points the bootstrap calls.
    for fn in (
        "renderTrackerImportTable",
        "renderGapTable",
        "renderTrace",
        "renderLlmTab",
        "renderPackage",
        "renderDerivation",
    ):
        assert fn in js, f"tracker.js missing {fn}"
    # Filters the Tracker Import tab promises.
    for filter_key in ("control", "owner", "status", "category"):
        assert f'"{filter_key}"' in js, f"missing import filter {filter_key}"
    # Filters the Evidence Gaps tab promises.
    assert '"gap_type"' in js
    assert '"severity"' in js
    assert '"poam_required"' in js


def test_tracker_js_lists_all_reasoners_for_llm_tab() -> None:
    js = (WEB / "tracker.js").read_text(encoding="utf-8")
    for reasoner in (
        "classify_ambiguous_row",
        "explain_for_assessor",
        "explain_for_executive",
        "explain_conmon_reasonableness",
        "explain_residual_risk_for_ao",
        "explain_derivation_trace",
        "draft_remediation_ticket",
        "draft_auditor_response",
        "evaluate_3pao_remediation_for_gap",
    ):
        assert reasoner in js, f"LLM Reasoning tab missing button for {reasoner}"
    # Endpoints the tab calls.
    assert "/api/ai/status" in js
    assert "/api/ai/reasoner" in js
    # Evidence-contract banner is embedded verbatim (so reviewers can read it
    # without leaving the page).
    assert "Evidence contract (binding)" in js


def test_tracker_js_derivation_steps_cover_full_chain() -> None:
    js = (WEB / "tracker.js").read_text(encoding="utf-8")
    expected_step_labels = (
        "Original tracker row",
        "Classifier rule",
        "EvidenceGap",
        "Eval result",
        "Control mapping",
        "KSI mapping",
        "Finding",
        "POA&M item",
        "Report sections",
    )
    for label in expected_step_labels:
        assert label in js, f"derivation chain missing step: {label}"


# ---------------------------------------------------------------------------
# sample-data/tracker/ — fallback artifacts
# ---------------------------------------------------------------------------


def test_sample_tracker_directory_present() -> None:
    assert SAMPLE.is_dir(), (
        "web/sample-data/tracker/ must ship so the explorer renders without a "
        "fresh tracker run"
    )


@pytest.mark.parametrize(
    "rel",
    [
        "scenario_from_tracker/tracker_items.json",
        "scenario_from_tracker/evidence_gaps.json",
        "agent_run_trace.json",
        "agent_run_summary.md",
        "tracker_gap_eval_results.json",
        "package_tracker/fedramp20x-package.json",
    ],
)
def test_sample_tracker_artifact_present(rel: str) -> None:
    assert (SAMPLE / rel).is_file(), f"missing fallback artifact: {rel}"


def test_sample_tracker_items_have_classification_signals() -> None:
    p = SAMPLE / "scenario_from_tracker" / "tracker_items.json"
    bundle = json.loads(p.read_text(encoding="utf-8"))
    rows = bundle.get("rows") or bundle.get("tracker_items") or []
    assert rows, "tracker_items.json must include rows"
    sample = rows[0]
    for key in ("row_index", "controls", "request_text", "category"):
        assert key in sample, f"tracker row missing {key}"


def test_sample_evidence_gaps_use_schema_2() -> None:
    p = SAMPLE / "scenario_from_tracker" / "evidence_gaps.json"
    bundle = json.loads(p.read_text(encoding="utf-8"))
    assert str(bundle.get("schema_version")) == "2.0"
    gaps = bundle.get("evidence_gaps") or []
    assert gaps, "expected at least one evidence_gap in fallback fixture"
    g = gaps[0]
    for k in (
        "gap_id",
        "source_item_id",
        "controls",
        "gap_type",
        "severity",
        "linked_ksi_ids",
        "recommended_artifact",
        "poam_required",
    ):
        assert k in g, f"evidence_gap missing field {k}"


def test_sample_agent_run_trace_has_15_categorical_tasks() -> None:
    p = SAMPLE / "agent_run_trace.json"
    trace = json.loads(p.read_text(encoding="utf-8"))
    tasks = trace.get("tasks") or []
    assert len(tasks) == 15, f"expected 15 categorical tasks, got {len(tasks)}"
    expected = {
        "ingest_tracker",
        "classify_rows",
        "normalize_evidence",
        "build_evidence_graph",
        "run_cloud_evals",
        "run_tracker_gap_evals",
        "run_agent_security_evals",
        "map_to_ksi",
        "generate_findings",
        "generate_poam",
        "build_package",
        "generate_reports",
        "reconcile",
        "validate_outputs",
        "explain_summary",
    }
    assert {t.get("task_id") for t in tasks} == expected
    for t in tasks:
        for k in (
            "task_id",
            "action_category",
            "policy_decision",
            "status",
            "started_at",
            "completed_at",
            "inputs",
            "outputs",
            "artifacts",
            "errors",
        ):
            assert k in t, f"task {t.get('task_id')} missing field {k}"


def test_sample_package_has_tracker_findings() -> None:
    p = SAMPLE / "package_tracker" / "fedramp20x-package.json"
    pkg = json.loads(p.read_text(encoding="utf-8"))
    findings = pkg.get("findings") or []
    assert findings, "package fallback must include findings"
    # The Derivation Trace tab walks FIND-TRACKER-* findings; ensure the
    # fallback contains at least one.
    assert any(
        str(f.get("finding_id", "")).startswith("FIND-TRACKER-") for f in findings
    ), "fallback package must contain at least one FIND-TRACKER-* finding"


# ---------------------------------------------------------------------------
# /api/ai/* endpoints (used by the LLM Reasoning tab)
# ---------------------------------------------------------------------------


def test_api_ai_status_lists_all_reasoners() -> None:
    from fastapi.testclient import TestClient

    from api.server import app

    c = TestClient(app)
    r = c.get("/api/ai/status")
    assert r.status_code == 200
    body = r.json()
    assert "llm_configured" in body
    assert "endpoint" in body
    assert set(body.get("reasoners", [])) == {
        "classify_ambiguous_row",
        "draft_auditor_response",
        "draft_remediation_ticket",
        "evaluate_3pao_remediation_for_gap",
        "explain_conmon_reasonableness",
        "explain_derivation_trace",
        "explain_for_assessor",
        "explain_for_executive",
        "explain_residual_risk_for_ao",
    }


def test_api_ai_reasoner_invokes_deterministic_fallback() -> None:
    from fastapi.testclient import TestClient

    from api.server import app

    c = TestClient(app)
    body = {
        "reasoner": "classify_ambiguous_row",
        "payload": {
            "tracker_row": {
                "row_index": 9,
                "request_text": "Show centralized log aggregation example.",
                "controls": ["AU-6"],
            },
            "deterministic_classification": {
                "gap_type": "unknown",
                "severity": "low",
            },
        },
    }
    r = c.post("/api/ai/reasoner", json=body)
    assert r.status_code == 200, r.text
    j = r.json()
    # Without an AI_API_KEY this MUST be deterministic, never LLM.
    assert j["source"] == "deterministic_fallback"
    assert j["gap_type"] in {
        "unknown",
        "centralized_log_missing",
        "local_to_central_log_correlation_missing",
        "alert_rule_missing",
        "alert_sample_missing",
    }


def test_api_ai_reasoner_rejects_unknown_reasoner() -> None:
    from fastapi.testclient import TestClient

    from api.server import app

    c = TestClient(app)
    r = c.post(
        "/api/ai/reasoner",
        json={"reasoner": "totally_made_up", "payload": {}},
    )
    # Pydantic rejects unknown literals before the dispatcher fires.
    assert r.status_code in (400, 422)
