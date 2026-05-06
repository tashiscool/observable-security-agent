"""Tests for RAG context debug output."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from core.rag_context_builder import build_rag_context
from core.rag_context_debug import rag_context_debug_document, write_rag_context_debug_document
from tests.test_rag_context_builder import NOW, _controls, _evidence


def test_selected_evidence_appears_with_reason() -> None:
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        account_ids=["123456789012"],
        asset_ids=["i-001"],
        evidence_artifacts=[_evidence("ev-selected", control_ids=["RA-5"])],
        controls=_controls(),
    )

    debug = rag_context_debug_document(bundle)

    selected = debug["selectedEvidence"][0]
    assert selected["evidenceId"] == "ev-selected"
    assert selected["relevanceReasons"] == ["MATCHED_ACCOUNT", "MATCHED_CONTROL", "MATCHED_RESOURCE"]
    assert selected["freshnessReason"] == "freshnessStatus=current"
    assert selected["trustReason"] == "trustLevel=authoritative"


def test_stale_and_wrong_account_sources_appear_in_excluded_sources() -> None:
    bundle = build_rag_context(
        user_request="Assess RA-5 in account 123456789012.",
        control_ids=["RA-5"],
        account_ids=["123456789012"],
        evidence_artifacts=[
            _evidence("ev-current", control_ids=["RA-5"]),
            _evidence("ev-stale", control_ids=["RA-5"], observed_at=NOW - timedelta(days=60), freshness_status="stale"),
            _evidence("ev-wrong-account", control_ids=["RA-5"], account_id="999999999999"),
        ],
        controls=_controls(),
    )

    debug = rag_context_debug_document(bundle)
    excluded = {row["sourceId"]: row["reasons"] for row in debug["excludedSources"]}

    assert "STALE" in excluded["ev-stale"]
    assert "WRONG_ACCOUNT" in excluded["ev-wrong-account"]


def test_missing_evidence_appears_in_debug_summary() -> None:
    bundle = build_rag_context(
        user_request="Assess AU-6.",
        control_ids=["AU-6"],
        evidence_artifacts=[_evidence("ev-ra5", control_ids=["RA-5"])],
        controls=_controls(),
    )

    debug = rag_context_debug_document(bundle)

    assert debug["missingEvidenceSummary"] == ["AU-6: no selected fresh, in-scope evidence is available."]
    assert "Use only supplied evidence" in debug["finalInstructions"]


def test_debug_output_is_deterministic(tmp_path: Path) -> None:
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[
            _evidence("ev-b", control_ids=["RA-5"]),
            _evidence("ev-a", control_ids=["RA-5"], resource_id="i-002"),
        ],
        controls=_controls(),
    )

    first = rag_context_debug_document(bundle)
    second = rag_context_debug_document(bundle)
    path = write_rag_context_debug_document(tmp_path / "debug-context.json", first)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert path.read_text(encoding="utf-8") == json.dumps(first, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_debug_context_cli_writes_json(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    output = tmp_path / "debug-context.json"

    proc = subprocess.run(
        [
            sys.executable,
            "agent.py",
            "debug-context",
            "--control",
            "RA-5",
            "--account",
            "111111111111",
            "--output",
            str(output),
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["originalRequest"] == "Debug RAG context for RA-5."
    assert data["parsedScope"]["controlIds"] == ["RA-5"]
    assert "selectedEvidence" in data
    assert "excludedSources" in data
