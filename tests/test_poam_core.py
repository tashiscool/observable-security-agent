"""Unit tests for POA&M generation and due-date rules."""

from __future__ import annotations

from datetime import date

from core.models import PoamItem
from core.pipeline_models import EvalStatus, PipelineEvalResult as PER, PipelineSemanticEvent as Sem
from core.poam import build_poam_generation, milestone_due_date_for_severity


def test_milestone_due_dates() -> None:
    ref = date(2026, 6, 1)
    assert milestone_due_date_for_severity("critical", ref) == date(2026, 6, 16)
    assert milestone_due_date_for_severity("high", ref) == date(2026, 7, 1)
    assert milestone_due_date_for_severity("moderate", ref) == date(2026, 8, 30)
    assert milestone_due_date_for_severity("low", ref) == date(2026, 11, 28)


def test_missing_poam_generates_row() -> None:
    sem = Sem(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="prod-api-01",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-1",
    )
    prior = [
        PER(
            eval_id="SI4_ALERT_INSTRUMENTATION",
            control_refs=["SI-4"],
            result=EvalStatus.FAIL,
            evidence=["x"],
            gap="No enabled alert.",
            machine={"severity": "high"},
        )
    ]
    rows, stats = build_poam_generation(
        prior,
        sem,
        existing_poam_items=[],
        seed_poam_rows=[],
        reference_date=date(2026, 1, 10),
    )
    assert stats["added"] >= 1
    assert any(r.get("Source Eval ID") == "SI4_ALERT_INSTRUMENTATION" for r in rows)
    due = next(r["Milestone Due Date"] for r in rows if r.get("Source Eval ID") == "SI4_ALERT_INSTRUMENTATION")
    assert due == "2026-02-09"


def test_existing_poam_not_duplicated_by_source_eval_id() -> None:
    sem = Sem(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="prod-api-01",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-1",
    )
    prior = [
        PER(
            eval_id="SI4_ALERT_INSTRUMENTATION",
            control_refs=["SI-4"],
            result=EvalStatus.FAIL,
            evidence=["x"],
            gap="gap",
            machine={"severity": "high"},
        )
    ]
    existing = [
        PoamItem(
            poam_id="POAM-EXIST",
            controls=["CA-5"],
            weakness_name="No enabled alert for public administrative-port exposure",
            weakness_description="prior",
            asset_identifier="prod-api-01",
            raw_severity="high",
            adjusted_risk_rating="high",
            status="open",
            planned_remediation="track",
            source_eval_id="SI4_ALERT_INSTRUMENTATION",
        )
    ]
    rows, stats = build_poam_generation(
        prior,
        sem,
        existing_poam_items=existing,
        seed_poam_rows=[],
        reference_date=date(2026, 1, 1),
    )
    assert stats["added"] == 0
    assert stats["skipped_duplicate"] == 1
    assert sum(1 for r in rows if r.get("Source Eval ID") == "SI4_ALERT_INSTRUMENTATION") == 1
