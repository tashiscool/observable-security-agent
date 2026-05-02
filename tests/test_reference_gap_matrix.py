"""``docs/reference_gap_matrix.md`` documents unique capabilities vs reference stacks."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GAP_MATRIX = ROOT / "docs" / "reference_gap_matrix.md"


def test_reference_gap_matrix_exists_and_states_unique_layer() -> None:
    assert GAP_MATRIX.is_file()
    text = GAP_MATRIX.read_text(encoding="utf-8")
    assert "**Our unique layer" in text or "Our unique layer" in text
    for phrase in (
        "evidence correlation",
        "FedRAMP 20x",
        "POA&M",
        "bounded",
        "deterministic evals",
    ):
        assert phrase.lower() in text.lower(), f"expected capability phrase near unique layer: {phrase!r}"
