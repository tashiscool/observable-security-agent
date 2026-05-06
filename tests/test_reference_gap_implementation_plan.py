"""Reference-driven gap plan remains explicit and competition-actionable."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "reference_driven_gap_implementation_plan.md"


def _text() -> str:
    assert PLAN.is_file()
    return PLAN.read_text(encoding="utf-8").lower()


def test_plan_names_actual_reference_driven_gaps() -> None:
    text = _text()
    for gap in (
        "reference/capability visibility",
        "3pao reasonableness",
        "live aws permission/confidence coverage",
        "ocsf normalization",
        "scanner adapter breadth",
        "inventory graph import",
        "ticketing exports",
        "conmon coverage",
        "public exposure detection",
        "evidence graph ui",
        "package diff/history",
        "ai backend status",
    ):
        assert gap in text


def test_plan_prioritizes_ui_and_adapter_work() -> None:
    text = _text()
    for phase in (
        "phase 1",
        "judge-visible auditability panels",
        "phase 2",
        "adapter breadth",
        "phase 3",
        "operator workbench",
        "phase 4",
        "live connector ergonomics",
    ):
        assert phase in text


def test_plan_keeps_reference_boundary_clear() -> None:
    text = _text()
    assert "do not rebuild" in text
    assert "not runtime dependencies" in text
    assert "deterministic artifacts remain the audit record" in text
    assert "do not commit live raw evidence" in text
