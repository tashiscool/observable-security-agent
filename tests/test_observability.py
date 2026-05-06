"""Tests for agent run logging and observability metrics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.domain_models import AgentRunLog, model_from_json, model_to_json
from core.observability import (
    aggregate_observability_metrics,
    create_run_log,
    failed_run_log,
    metrics_markdown,
    run_with_observability,
    write_metrics_json,
    write_metrics_markdown,
    write_run_log,
    load_run_logs,
)
from tests.test_assurance_package import _build_package


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def test_successful_run_log_round_trip() -> None:
    log = create_run_log(
        workflow="evidence_normalization",
        input_payload={"source": "fixture"},
        started_at=NOW,
        completed_at=NOW + timedelta(milliseconds=125),
        evidence_ids=["ev-001"],
        finding_ids=["nf-001"],
        control_ids=["RA-5"],
        warnings=["minor warning"],
        human_review_required=True,
    )

    assert log.status == "SUCCESS"
    assert log.duration_ms == 125
    assert log.input_hash.startswith("sha256:")
    assert log.finding_ids == ["nf-001"]
    assert log.warnings == ["minor warning"]
    assert model_from_json(AgentRunLog, model_to_json(log)) == log


def test_failed_run_log_records_exception_and_collector_status() -> None:
    log = failed_run_log(
        workflow="evidence_normalization",
        input_payload={"source": "collector"},
        started_at=NOW,
        error=RuntimeError("collector denied"),
        collector_failed=True,
    )

    assert log.status == "COLLECTOR_FAILED"
    assert log.decision == "failed"
    assert log.schema_valid is False
    assert log.errors == ["collector denied"]


def test_run_with_observability_catches_exception_without_silent_failure() -> None:
    def boom():
        raise ValueError("bad input")

    result, log = run_with_observability(
        workflow="deterministic_validation",
        input_payload={"control": "RA-5"},
        func=boom,
    )

    assert result is None
    assert log.status == "FAILED"
    assert log.errors == ["bad input"]


def test_run_log_append_and_load(tmp_path) -> None:
    path = tmp_path / "agent-runs.jsonl"
    log = create_run_log(
        workflow="control_mapping",
        input_payload={"n": 1},
        started_at=NOW,
        completed_at=NOW,
        control_ids=["RA-5"],
    )

    write_run_log(path, log)

    assert load_run_logs(path) == [log]


def test_metrics_aggregation_counts_core_signals() -> None:
    package = _build_package()
    package["evidence"][0]["freshnessStatus"] = "stale"
    package["evidence"][0]["observedAt"] = (NOW - timedelta(hours=25)).isoformat()
    success = create_run_log(
        workflow="rag_context_build",
        input_payload={"request": "RA-5"},
        started_at=NOW,
        completed_at=NOW,
    )
    failed = failed_run_log(
        workflow="assurance_package_generation",
        input_payload={"package": "pkg"},
        started_at=NOW,
        error="schema failed",
    )
    context = {
        "selectedEvidence": [{"evidenceId": "ev-001"}],
        "excludedSources": [{"sourceId": "ev-002", "reasons": ["STALE"]}],
    }

    metrics = aggregate_observability_metrics(
        assurance_package=package,
        run_logs=[success, failed],
        rag_contexts=[context],
        assets=[{"assetId": "asset-1", "resourceId": "i-001", "evidenceIds": []}],
    )

    assert metrics["retrieval_hit_rate"] == 0.5
    assert metrics["stale_evidence_count"] == 1
    assert metrics["missing_evidence_count"] >= 1
    assert metrics["unsupported_claim_count"] >= 1
    assert metrics["source_document_count"] == 1
    assert metrics["tool_call_success_rate"] == 0.5
    assert metrics["tool_call_failure_rate"] == 0.5
    assert metrics["schema_validation_failure_count"] == 1
    assert metrics["high_findings_open"] == 1
    assert metrics["critical_findings_open"] == 0
    assert "AC-2" in metrics["controls_without_evidence"]
    assert metrics["assets_without_scan"] == ["asset-1"]
    assert metrics["control_mapping_confidence_counts"]


def test_reviewer_override_rate_calculated() -> None:
    package = _build_package()
    package["humanReviewDecisions"].append(
        {
            "reviewDecisionId": "hrd-override",
            "recommendationId": package["agentRecommendations"][0]["recommendationId"],
            "controlId": "RA-5",
            "findingIds": [],
            "evidenceIds": ["ev-001"],
            "reviewer": "AO",
            "decision": "REJECTED",
            "justification": "Reviewer override for test.",
            "timestamp": NOW.isoformat(),
        }
    )

    metrics = aggregate_observability_metrics(assurance_package=package)

    assert metrics["reviewer_override_rate"] == 0.5
    assert metrics["recommendation_acceptance_rate"] > 0


def test_metrics_outputs_json_and_markdown(tmp_path) -> None:
    metrics = aggregate_observability_metrics(assurance_package=_build_package())
    json_path = tmp_path / "metrics.json"
    md_path = tmp_path / "metrics.md"

    write_metrics_json(json_path, metrics)
    write_metrics_markdown(md_path, metrics)

    assert json_path.read_text(encoding="utf-8").startswith("{")
    text = md_path.read_text(encoding="utf-8")
    assert text == metrics_markdown(metrics)
    assert "# Observability metrics" in text
