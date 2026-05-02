"""Deterministic explain API (no AI_API_KEY required)."""

from __future__ import annotations

import pytest

from api.explain import _grounded_system_preamble, build_grounded_user_message, redact_secrets, run_explain


def test_explain_trace_ra5_deterministic() -> None:
    out = run_explain(
        mode="trace_derivation",
        question="Why fail?",
        selected_eval={
            "eval_id": "RA5_SCANNER_SCOPE_COVERAGE",
            "result": "FAIL",
            "summary": "Missing targets",
            "gap": "prod-api-01 not in scanner_targets.csv",
        },
        related_evidence=None,
        related_graph=None,
        related_poam=[],
    )
    assert "answer" in out
    assert "RA5_SCANNER_SCOPE_COVERAGE" in out["answer"]
    assert "scanner" in out["answer"].lower()
    assert out.get("used_artifacts")
    assert isinstance(out.get("warnings"), list)


def test_explain_ksi_flat_payload_includes_id_and_evidence_refs() -> None:
    out = run_explain(
        mode="explain_ksi",
        audience="assessor",
        question=None,
        selected_ksi={
            "ksi_id": "KSI-LOG-01",
            "theme": "Logging",
            "title": "Centralized logging",
            "validation_mode": "hybrid",
            "legacy_controls": {"rev4": ["AU-6"], "rev5": ["AU-6"]},
            "pass_fail_criteria": [
                {
                    "criteria_id": "LOG-CRI-001",
                    "description": "Control-plane logs enabled.",
                    "validation_type": "automated",
                    "evidence_required": ["central_log_source_export"],
                }
            ],
            "evidence_sources": ["central_log_source_export"],
        },
        related_evidence={
            "ksi_validation_row": {
                "ksi_id": "KSI-LOG-01",
                "status": "FAIL",
                "evidence_refs": [{"artifact": "eval_results.json", "role": "primary"}],
            }
        },
    )
    assert "KSI-LOG-01" in out["answer"]
    assert "eval_results.json" in out["answer"]
    assert "evidence_refs" in out["answer"].lower() or "eval_results" in out["answer"]


def test_reconciliation_failure_explains_mismatch() -> None:
    out = run_explain(
        mode="reconciliation_failure",
        audience="assessor",
        related_reconciliation={
            "overall_status": "fail",
            "checks": [
                {
                    "id": "REC-003",
                    "status": "fail",
                    "description": "Executive summary counts",
                    "detail": "count mismatch between package summary and executive headline",
                }
            ],
        },
    )
    assert "REC-003" in out["answer"]
    assert "mismatch" in out["answer"].lower()


def test_prompt_redacts_secret_keys() -> None:
    msg = build_grounded_user_message(
        mode="explain_eval",
        question=None,
        audience="engineer",
        selected_eval={"eval_id": "X"},
        related_evidence={"api_key": "super-secret-token-value", "safe": "ok"},
        related_graph=None,
        related_poam=[],
        fedramp20x_context=None,
        selected_ksi=None,
        selected_finding=None,
        selected_poam=None,
        related_reconciliation=None,
    )
    assert "super-secret-token-value" not in msg
    assert "[REDACTED]" in msg


def test_redact_secrets_nested() -> None:
    d = redact_secrets({"nested": {"client_secret": "abc123"}})
    assert d["nested"]["client_secret"] == "[REDACTED]"


def test_fallback_without_api_key_new_modes() -> None:
    """Deterministic path when AI_API_KEY is unset."""
    out_trace = run_explain(
        mode="trace_ksi_evidence",
        audience="engineer",
        selected_ksi={"ksi_id": "KSI-X", "pass_fail_criteria": [], "evidence_sources": []},
        related_evidence={"ksi_validation_row": {"ksi_id": "KSI-X", "status": "PASS", "evidence_refs": []}},
    )
    assert "KSI-X" in out_trace["answer"]
    assert any("deterministic" in str(u).lower() for u in out_trace["used_artifacts"])

    out_cw_miss = run_explain(mode="explain_crosswalk", audience="engineer", related_evidence={})
    assert "missing evidence" in out_cw_miss["answer"].lower()

    out_cw = run_explain(
        mode="explain_crosswalk",
        audience="engineer",
        related_evidence={"control_crosswalk": {"rev4_to_rev5": [{"rev4_control_id": "AC-2", "rev5_control_id": "AC-2"}]}},
    )
    assert "AC-2" in out_cw["answer"]

    for mode in ("executive_summary", "ao_risk_brief", "poam_remediation_plan"):
        out = run_explain(
            mode=mode,
            audience="engineer",
            selected_ksi={"ksi_id": "KSI-X", "pass_fail_criteria": [], "evidence_sources": []},
            related_evidence={"ksi_validation_row": {"ksi_id": "KSI-X", "status": "PASS", "evidence_refs": []}},
            selected_poam={"poam_id": "POAM-1", "finding_id": "F-1", "title": "Fix logs"},
            selected_finding={"finding_id": "F-1", "recommended_remediation": "Enable forwarding"},
        )
        assert "answer" in out
        assert out["used_artifacts"]


def test_explain_post_api_flat_body() -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from api.server import app

    client = TestClient(app)
    r = client.post(
        "/api/explain",
        json={
            "mode": "explain_ksi",
            "audience": "executive",
            "selected_ksi": {"ksi_id": "KSI-A", "theme": "T", "title": "Title"},
            "related_evidence": {
                "ksi_validation_row": {"ksi_id": "KSI-A", "status": "PARTIAL", "evidence_refs": [{"artifact": "x.json"}]},
            },
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "KSI-A" in body["answer"]


def test_explain_health_import() -> None:
    pytest.importorskip("fastapi")
    from api.server import health

    assert health() == {"status": "ok"}


def test_system_prompt_includes_evidence_contract() -> None:
    sysm = _grounded_system_preamble(audience="assessor")
    assert "Evidence contract" in sysm or "EVIDENCE" in sysm
    assert "missing evidence".lower() in sysm.lower()
    assert "sample_alert_ref" in sysm
    assert "linked_ticket_id" in sysm


def test_user_prompt_requires_named_artifacts() -> None:
    msg = build_grounded_user_message(
        mode="explain_eval",
        question="Why?",
        audience="engineer",
        selected_eval={"eval_id": "CM8_INVENTORY_RECONCILIATION", "result": "FAIL"},
        related_evidence={"correlations": []},
        related_graph={"edges": [{"a": 1}], "nodes": []},
        related_poam=[],
        fedramp20x_context=None,
        selected_ksi=None,
        selected_finding=None,
        selected_poam=None,
        related_reconciliation=None,
    )
    assert "eval_results.json" in msg
    assert "correlations.json" in msg
    assert "evidence_graph.json" in msg
    assert "Evidence contract" in msg or "binding" in msg


def test_missing_evidence_phrase_on_crosswalk_gap() -> None:
    out = run_explain(mode="explain_crosswalk", audience="engineer", related_evidence={})
    assert "missing evidence" in out["answer"].lower()


def test_cm3_deterministic_no_invented_ticket_id() -> None:
    """Gap describes missing linkage without supplying a linked_ticket_id — do not fabricate IDs."""
    out = run_explain(
        mode="trace_derivation",
        audience="engineer",
        selected_eval={
            "eval_id": "CM3_CHANGE_EVIDENCE_LINKAGE",
            "result": "FAIL",
            "summary": "Change evidence linkage failed.",
            "gap": "Event fixture:abc-001 has no linked ticket for CM-3 evidence flags.",
            "evidence": [],
        },
        related_evidence=None,
        related_graph=None,
        related_poam=[],
    )
    assert "missing evidence" in out["answer"].lower()
    assert "linked_ticket_id" in out["answer"].lower()
    assert "CHG-12345" not in out["answer"]
    assert "TICK-99999" not in out["answer"]


def test_si4_deterministic_no_alert_fired_claim() -> None:
    out = run_explain(
        mode="explain_eval",
        audience="engineer",
        selected_eval={
            "eval_id": "SI4_ALERT_INSTRUMENTATION",
            "result": "FAIL",
            "summary": "Alert gaps",
            "gap": "Rule r1 has no sample_alert_ref and no recorded last_fired (no proof of firing).",
        },
        related_evidence=None,
        related_graph=None,
        related_poam=[],
    )
    assert "missing evidence" in out["answer"].lower()
    lower = out["answer"].lower()
    assert "alert fired" not in lower
    assert "eval_results.json" in lower


def test_fallback_without_api_key_still_grounded(monkeypatch) -> None:
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = run_explain(
        mode="trace_derivation",
        audience="assessor",
        selected_eval={
            "eval_id": "RA5_SCANNER_SCOPE_COVERAGE",
            "result": "FAIL",
            "summary": "Scope gap",
            "gap": "Asset prod-x not listed in scanner_targets.csv",
        },
        related_evidence=None,
        related_graph=None,
        related_poam=[],
    )
    assert "eval_results.json" in out["answer"]
    assert "scanner_targets.csv" in out["answer"].lower() or "RA5" in out["answer"]
    assert "deterministic" in " ".join(out["used_artifacts"]).lower() or out.get("warnings")
