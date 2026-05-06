"""Competition readiness harness contracts."""

from __future__ import annotations

from pathlib import Path

import scripts.buildlab_readiness as br

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_readiness_uses_live_validation_for_green_path(monkeypatch, tmp_path: Path) -> None:
    modes: dict[str, str] = {}

    def fake_run_agent(args: list[str], cwd: Path, env=None) -> tuple[int, str]:
        scenario = args[args.index("--scenario") + 1]
        out_dir = Path(args[args.index("--output-dir") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "scenario.txt").write_text(scenario, encoding="utf-8")
        return 0, ""

    def fake_validate(output_dir: Path, *, mode: str = "demo") -> list[str]:
        scenario = (output_dir / "scenario.txt").read_text(encoding="utf-8")
        modes[scenario] = mode
        return []

    monkeypatch.setattr(br, "_run_agent", fake_run_agent)
    monkeypatch.setattr("core.output_validation.validate_evidence_package", fake_validate)

    rows: list[br.Row] = []
    assert br._fixture_demos(rows, ROOT, tmp_path) is True

    assert modes["scenario_public_admin_vuln_event"] == "demo"
    assert modes["scenario_agentic_risk"] == "demo"
    assert modes["scenario_20x_readiness"] == "live"
    assert all(r.status == "PASS" for r in rows)


def test_web_readiness_checks_assessor_matrix_and_explorer_contract() -> None:
    rows: list[br.Row] = []

    assert br._web_readiness(rows, ROOT) is True

    names = {r.name for r in rows if r.status == "PASS"}
    assert "sample-data assessor workpapers" in names
    assert "Explorer assessor UI contract" in names


def test_curated_live_artifact_guard_is_part_of_readiness() -> None:
    rows: list[br.Row] = []

    assert br._guard_curated_live_artifacts(rows, ROOT) is True

    assert any(r.status == "PASS" and r.name == "no live AWS ids in curated artifacts" for r in rows)
