"""Tests for the bounded LLM-backed reasoning layer (`ai/`).

Covers:

* No-API-key path → every reasoner returns ``DETERMINISTIC_FALLBACK``.
* Ambiguous-row classifier preserves ``unknown`` and never invents a type.
* Every prompt embeds the binding evidence contract.
* Sanitization rewrites alert/ticket/log-existence claims to
  ``**missing evidence**`` whenever the input declares them missing.
* Monkey-patched LLM path returns the structured Pydantic shape and the LLM
  cannot escape the closed gap_type set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from ai import (
    AuditorResponseDraft,
    EvidenceCitation,
    ExplanationResponse,
    ReasoningSource,
    RemediationTicketDraft,
    RowClassificationReasoning,
    classify_ambiguous_row,
    draft_auditor_response,
    draft_remediation_ticket,
    explain_conmon_reasonableness,
    explain_derivation_trace,
    explain_for_assessor,
    explain_for_executive,
    explain_residual_risk_for_ao,
    evaluate_3pao_remediation_for_gap,
    is_llm_configured,
    llm_backend_status,
)
from ai import reasoning as ai_reasoning
from ai.prompts import (
    ALLOWED_GAP_TYPES,
    JSON_OUTPUT_DIRECTIVE,
    build_assessor_explanation_messages,
    build_auditor_response_messages,
    build_classify_row_messages,
    build_conmon_reasonableness_messages,
    build_derivation_trace_messages,
    build_executive_summary_messages,
    build_remediation_ticket_messages,
    build_residual_risk_messages,
    redact_secrets_for_prompt,
)
from ai.reasoning import (
    MISSING_EVIDENCE_MARK,
    sanitize_no_invented_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


# Ensure the LLM path is OFF for the entire test session unless a test opts in.
@pytest.fixture(autouse=True)
def _no_ai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_BASE", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)


# ---------------------------------------------------------------------------
# Configuration / environment
# ---------------------------------------------------------------------------


class TestEnvironment:
    def test_default_environment_has_no_key(self) -> None:
        assert is_llm_configured() is False

    def test_setting_key_flips_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")
        assert is_llm_configured() is True

    def test_ollama_backend_can_be_configured_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AI_BACKEND", "ollama")
        monkeypatch.setenv("AI_API_BASE", "http://127.0.0.1:11434/v1")
        monkeypatch.setenv("AI_MODEL", "llama3.1")
        assert is_llm_configured() is True
        status = llm_backend_status(reasoners=["explain_conmon_reasonableness"])
        assert status["backend"] == "ollama"
        assert status["requires_api_key"] is False
        assert "explain_conmon_reasonableness" in status["reasoners"]

    def test_bedrock_litellm_model_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")
        monkeypatch.setenv("AI_API_BASE", "http://127.0.0.1:4000/v1")
        monkeypatch.setenv("AI_MODEL", "bedrock/anthropic.claude-3-sonnet-20240229-v1:0")
        status = llm_backend_status()
        assert status["configured"] is True
        assert "bedrock" in status["backend"]


# ---------------------------------------------------------------------------
# Prompts: every prompt embeds the evidence contract
# ---------------------------------------------------------------------------


_ALL_PROMPT_BUILDERS = [
    lambda: build_classify_row_messages(
        tracker_row={"row_index": 1, "request_text": "x"},
        deterministic_classification={"gap_type": "unknown"},
    ),
    lambda: build_assessor_explanation_messages(
        eval_record={"eval_id": "X", "result": "FAIL"}
    ),
    lambda: build_executive_summary_messages(
        package_summary={"overall_status": "FAIL"}
    ),
    lambda: build_conmon_reasonableness_messages(
        conmon_result={"summary": {"obligations": 1}, "obligation_assessments": []}
    ),
    lambda: build_residual_risk_messages(finding={"finding_id": "F-1"}),
    lambda: build_derivation_trace_messages(trace={"workflow": "x", "tasks": []}),
    lambda: build_remediation_ticket_messages(finding={"finding_id": "F-2"}),
    lambda: build_auditor_response_messages(question="any?"),
]


class TestPromptsContractEmbedded:
    @pytest.mark.parametrize("builder", _ALL_PROMPT_BUILDERS)
    def test_system_message_contains_evidence_contract(self, builder) -> None:  # type: ignore[no-untyped-def]
        sysm, _ = builder()
        assert "Evidence contract" in sysm
        assert "missing evidence" in sysm.lower()
        assert "Use ONLY the JSON artifacts" in sysm

    @pytest.mark.parametrize("builder", _ALL_PROMPT_BUILDERS)
    def test_user_message_requires_json_output(self, builder) -> None:  # type: ignore[no-untyped-def]
        _, userm = builder()
        assert JSON_OUTPUT_DIRECTIVE in userm
        # Force JSON-only response, no surrounding prose.
        assert "SINGLE JSON object" in userm

    def test_classify_row_user_lists_allowed_gap_types(self) -> None:
        _, userm = build_classify_row_messages(
            tracker_row={"row_index": 1, "request_text": "x"},
            deterministic_classification={"gap_type": "unknown"},
        )
        # The closed allow-list of gap types must appear verbatim.
        assert "centralized_log_missing" in userm
        assert "exploitation_review_missing" in userm
        assert "unknown" in userm

    def test_redact_secrets_replaces_sensitive_keys(self) -> None:
        cleaned = redact_secrets_for_prompt(
            {"name": "ok", "api_key": "sk-XYZ", "nested": {"secret_token": "abc"}}
        )
        assert cleaned["api_key"] == "[REDACTED]"
        assert cleaned["nested"]["secret_token"] == "[REDACTED]"
        assert cleaned["name"] == "ok"


# ---------------------------------------------------------------------------
# No-API-key path: every reasoner returns DETERMINISTIC_FALLBACK
# ---------------------------------------------------------------------------


class TestNoKeyPath:
    def test_classify_ambiguous_row_returns_unknown_fallback(self) -> None:
        out = classify_ambiguous_row(
            tracker_row={
                "row_index": 99,
                "request_text": "ambiguous request that no rule matches",
                "controls": ["AC-99"],
            },
            deterministic_classification={
                "gap_type": "unknown",
                "severity": "low",
                "recommended_artifact": None,
                "recommended_validation": None,
                "poam_required": False,
            },
        )
        assert isinstance(out, RowClassificationReasoning)
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        # Deterministic fallback never invents a gap_type.
        assert out.gap_type == "unknown"
        assert out.confidence == "low"

    def test_assessor_explanation_fallback(self) -> None:
        out = explain_for_assessor(
            eval_record={
                "eval_id": "AU6_CENTRALIZED_LOG_COVERAGE",
                "result": "FAIL",
                "severity": "high",
                "summary": "central log coverage missing",
                "gap": "no central log path",
                "control_refs": ["AU-6"],
            }
        )
        assert isinstance(out, ExplanationResponse)
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.audience == "assessor"
        assert "AU6_CENTRALIZED_LOG_COVERAGE" in out.headline
        # All citations point at named artifacts.
        assert all(isinstance(c, EvidenceCitation) for c in out.citations)
        assert any(c.artifact == "eval_results.json" for c in out.citations)

    def test_executive_summary_fallback(self) -> None:
        out = explain_for_executive(
            package_summary={
                "overall_status": "PARTIAL",
                "ksi_total": 51,
                "ksi_pass": 30,
                "ksi_partial": 5,
                "ksi_fail": 16,
            },
            fail_partial_findings=[{"finding_id": "F-1"}],
            open_poam=[{"poam_id": "P-1"}],
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert "readiness" in out.headline.lower()
        assert any(c.artifact == "fedramp20x-package.json" for c in out.citations)

    def test_executive_summary_fallback_marks_missing_summary_fields(self) -> None:
        out = explain_for_executive(package_summary={})
        # Each absent KSI field must surface in missing_evidence; nothing invented.
        assert any(
            "ksi_total" in m or "summary" in m for m in out.missing_evidence
        )

    def test_conmon_reasonableness_fallback(self) -> None:
        out = explain_conmon_reasonableness(
            conmon_result={
                "catalog_name": "FedRAMP ConMon",
                "summary": {
                    "obligations": 17,
                    "reasonable": 0,
                    "partial": 3,
                    "missing": 14,
                    "tracker_rows": 19,
                },
                "evidence_ecosystems": {
                    "aws": {"systems": ["AWS CloudTrail"]},
                    "siem": {"systems": ["Splunk"]},
                    "os_and_endpoint": {"systems": ["Wazuh"]},
                    "ticketing": {"systems": ["Smartsheet", "Jira", "ServiceNow"]},
                },
                "obligation_assessments": [
                    {
                        "obligation_id": "CONMON-CONT-001",
                        "cadence": "continuous",
                        "coverage": "missing",
                        "reasonableness_gaps": ["No tracker row maps to this obligation."],
                    }
                ],
            }
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.referenced_eval_id == "CONMON_REASONABLENESS"
        assert "Smartsheet/Jira/ServiceNow" in out.body

    def test_3pao_reasonable_test_fails_when_related_artifacts_are_only_ticket_shells(self) -> None:
        out = evaluate_3pao_remediation_for_gap(
            evidence_gap={
                "gap_id": "gap-cm3",
                "gap_type": "sia_missing",
                "controls": ["CM-3", "CM-4"],
                "title": "SIA missing for sampled change",
                "description": (
                    "For a sample of system changes, provide security impact analysis, "
                    "testing evidence, approval, and implementation documentation."
                ),
                "recommended_artifact": "tickets.json field security_impact_analysis=true with SIA attachment",
            },
            related_artifacts={
                "tickets.json": {
                    "tickets": [
                        {
                            "id": "CHG-1001",
                            "summary": "Patch deployment ticket",
                            "status": "closed",
                        }
                    ]
                }
            },
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.reasonable_test_passed is False
        assert any(f.status == "fail" for f in out.artifact_sufficiency)
        assert any("security impact" in f.requirement for f in out.artifact_sufficiency)
        assert any("artifact_sufficiency" in m for m in out.missing_evidence)

    def test_3pao_reasonable_test_does_not_treat_tracker_text_as_proof(self) -> None:
        out = evaluate_3pao_remediation_for_gap(
            evidence_gap={
                "gap_id": "gap-inv",
                "gap_type": "inventory_mismatch",
                "controls": ["CM-8"],
                "title": "Inventory reconciliation missing",
                "description": "Provide reconciled inventory and discovered asset export.",
                "recommended_artifact": "declared_inventory.csv reconciled against discovered_assets.json",
            },
            related_artifacts={
                "tracker_items.json": {
                    "rows": [
                        {
                            "request_text": (
                                "Provide inventory reconciliation for assets with discrepancies."
                            )
                        }
                    ]
                }
            },
        )
        assert out.reasonable_test_passed is False
        assert out.artifact_sufficiency[0].requirement == "authoritative proof artifact supplied"
        assert "not proof" in out.artifact_sufficiency[0].evidence

    def test_3pao_reasonable_test_passes_when_sub_requirements_are_present(self) -> None:
        out = evaluate_3pao_remediation_for_gap(
            evidence_gap={
                "gap_id": "gap-cm3-pass",
                "gap_type": "sia_missing",
                "controls": ["CM-3", "CM-4"],
                "title": "SIA missing for sampled change",
                "description": (
                    "For a sample of system changes, provide security impact analysis, "
                    "testing evidence, approval, and implementation documentation."
                ),
                "recommended_artifact": "tickets.json field security_impact_analysis=true with SIA attachment",
            },
            related_artifacts={
                "tickets.json": {
                    "tickets": [
                        {
                            "id": "CHG-1002",
                            "security_impact_analysis": "SIA completed with security impact determination.",
                            "approval": "CAB approved; AO routing complete.",
                            "testing": "Smoke test and verification passed after deployment.",
                        }
                    ]
                }
            },
        )
        assert out.reasonable_test_passed is True
        assert out.artifact_sufficiency
        assert all(f.status == "pass" for f in out.artifact_sufficiency)
        assert not any("artifact_sufficiency" in m for m in out.missing_evidence)

    def test_3pao_sufficiency_rules_are_config_driven(self) -> None:
        cfg = yaml.safe_load((ROOT / "config" / "3pao-sufficiency-rules.yaml").read_text(encoding="utf-8"))
        assert "checks" in cfg
        assert "sia_missing" in cfg["checks"]
        assert cfg["context_artifact_exclusions"]
        assert any(
            "security impact" in item["requirement"]
            for item in cfg["checks"]["sia_missing"]
        )

    def test_residual_risk_fallback(self) -> None:
        out = explain_residual_risk_for_ao(
            finding={
                "finding_id": "FIND-TRACKER-001",
                "severity": "high",
                "title": "central log gap",
            },
            poam={"poam_id": "POAM-AUTO-1"},
            related_ksi={"ksi_id": "KSI-LOG-01"},
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.referenced_finding_id == "FIND-TRACKER-001"
        assert out.referenced_ksi_id == "KSI-LOG-01"

    def test_derivation_trace_fallback(self) -> None:
        out = explain_derivation_trace(
            trace={
                "workflow": "tracker-to-20x",
                "overall_status": "success",
                "tasks": [
                    {
                        "task_id": "ingest_tracker",
                        "status": "success",
                        "policy_decision": {"category": "autonomous"},
                    },
                    {
                        "task_id": "explain_summary",
                        "status": "success",
                        "policy_decision": {"category": "autonomous"},
                    },
                ],
            }
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert "tracker-to-20x" in out.headline
        assert "ingest_tracker" in out.body
        assert "explain_summary" in out.body

    def test_remediation_ticket_fallback(self) -> None:
        out = draft_remediation_ticket(
            finding={
                "finding_id": "F-9",
                "severity": "critical",
                "title": "exposed admin port",
                "controls": ["SC-7"],
                "recommended_remediation": "Restrict 0.0.0.0/0 ingress on the production SG.",
            }
        )
        assert isinstance(out, RemediationTicketDraft)
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.draft_ticket_id == "DRAFT-TICKET-F-9"
        assert out.severity == "critical"
        assert out.submitted_externally is False
        assert "Draft only" in out.note
        # Acceptance criteria must include a deterministic re-validation step.
        assert any("re-run" in c.lower() for c in out.acceptance_criteria)

    def test_auditor_response_fallback_with_evidence_gap(self) -> None:
        out = draft_auditor_response(
            question="Where is centralized log evidence for asset prod-web-1?",
            evidence_gap={
                "gap_id": "GAP-LOG-1",
                "gap_type": "centralized_log_missing",
                "controls": ["AU-6"],
                "recommended_artifact": "central_log_sources.json",
                "recommended_validation": "AU6_CENTRALIZED_LOG_COVERAGE",
            },
        )
        assert isinstance(out, AuditorResponseDraft)
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert "evidence_gaps.json" in out.cited_artifacts
        assert out.submitted_externally is False
        assert out.confidence in {"low", "moderate", "high"}

    def test_auditor_response_fallback_without_inputs_marks_missing(self) -> None:
        out = draft_auditor_response(question="Anything?")
        assert out.confidence == "low"
        assert "evidence_gap" in out.missing_evidence
        assert "eval_record" in out.missing_evidence
        # The fallback must say `missing evidence` somewhere visible.
        assert "missing evidence" in out.response_md.lower()


# ---------------------------------------------------------------------------
# Sanitization: never claim missing alert/ticket/log exists
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_alert_existence_claim_is_rewritten_when_missing(self) -> None:
        text = "We confirm that an alert was triggered for the suspicious activity."
        out, warnings = sanitize_no_invented_evidence(
            text, missing_evidence=["sample_alert_ref", "last_fired"]
        )
        assert MISSING_EVIDENCE_MARK in out
        assert "alert was triggered" not in out
        assert any("alert firing" in w for w in warnings)

    def test_ticket_existence_claim_is_rewritten_when_missing(self) -> None:
        text = "JIRA-1234 was filed; the ticket exists in the change record."
        out, warnings = sanitize_no_invented_evidence(
            text, missing_evidence=["linked_ticket_id"]
        )
        # The invented JIRA-1234 must NOT appear verbatim.
        assert "JIRA-1234" not in out
        assert MISSING_EVIDENCE_MARK in out
        assert any("ticket linkage" in w for w in warnings)

    def test_log_existence_claim_is_rewritten_when_missing(self) -> None:
        text = "Splunk contains the audit log for the asset, central logs are active."
        out, warnings = sanitize_no_invented_evidence(
            text, missing_evidence=["central_log"]
        )
        assert "Splunk contains" not in out
        assert "central logs are active" not in out
        assert MISSING_EVIDENCE_MARK in out
        assert any("centralized log" in w for w in warnings)

    def test_no_changes_when_input_does_not_declare_missing(self) -> None:
        text = "The alert was triggered and JIRA-1234 was filed."
        out, warnings = sanitize_no_invented_evidence(text, missing_evidence=[])
        assert out == text
        assert warnings == []

    def test_unrelated_text_is_untouched(self) -> None:
        text = "FIPS 140-3 cryptographic module verified by CMVP listing."
        out, warnings = sanitize_no_invented_evidence(
            text, missing_evidence=["sample_alert_ref"]
        )
        assert out == text
        assert warnings == []


# ---------------------------------------------------------------------------
# Integration: sanitization runs through the public reasoners
# ---------------------------------------------------------------------------


class TestPublicReasonersDoNotInventMissingThings:
    """End-to-end: even if an LLM tried to claim a missing thing exists, the
    public reasoner must rewrite it before returning to the caller."""

    def test_assessor_sanitizes_alert_claim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force LLM path on with a fake response that ASSERTS an alert fired.
        monkeypatch.setenv("AI_API_KEY", "test-key")

        def fake_call(**_kwargs: Any) -> str:
            return json.dumps(
                {
                    "source": "llm",
                    "audience": "assessor",
                    "headline": "alert fired for prod-web-1",
                    "body": "An alert was triggered for prod-web-1; the ticket exists.",
                    "citations": [{"artifact": "eval_results.json"}],
                    "missing_evidence": ["sample_alert_ref", "linked_ticket_id"],
                    "warnings": [],
                    "referenced_eval_id": "SI4_ALERT_INSTRUMENTATION",
                    "referenced_ksi_id": None,
                    "referenced_finding_id": None,
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = explain_for_assessor(
            eval_record={
                "eval_id": "SI4_ALERT_INSTRUMENTATION",
                "result": "FAIL",
                "severity": "high",
                "summary": "no alerts present",
            }
        )
        assert out.source == ReasoningSource.LLM
        # The body must NOT keep the asserted "alert was triggered" / "ticket exists" claims.
        assert "alert was triggered" not in out.body.lower()
        assert "ticket exists" not in out.body.lower()
        assert MISSING_EVIDENCE_MARK in out.body
        assert any("alert firing" in w for w in out.warnings)
        assert any("ticket linkage" in w for w in out.warnings)

    def test_remediation_ticket_sanitizes_log_claim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")

        def fake_call(**_kwargs: Any) -> str:
            return json.dumps(
                {
                    "source": "llm",
                    "draft_ticket_id": "DRAFT-TICKET-F-1",
                    "title": "Confirm Splunk contains the audit log",
                    "description_md": (
                        "Splunk contains the centralized audit log for the asset; "
                        "central logs are active and the ticket exists."
                    ),
                    "severity": "high",
                    "controls": ["AU-6"],
                    "affected_artifacts": ["fedramp20x-package.json"],
                    "acceptance_criteria": ["Re-run agent.py validate-outputs."],
                    "citations": [{"artifact": "fedramp20x-package.json"}],
                    "missing_evidence": ["central_log", "linked_ticket_id"],
                    "warnings": [],
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = draft_remediation_ticket(
            finding={
                "finding_id": "F-1",
                "severity": "high",
                "title": "central log evidence missing",
                "controls": ["AU-6"],
            }
        )
        assert out.source == ReasoningSource.LLM
        assert "Splunk contains" not in out.description_md
        assert "central logs are active" not in out.description_md
        assert "ticket exists" not in out.description_md
        assert MISSING_EVIDENCE_MARK in out.description_md

    def test_auditor_response_sanitizes_invented_jira_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")

        def fake_call(**_kwargs: Any) -> str:
            return json.dumps(
                {
                    "source": "llm",
                    "question": "Show evidence of central log ingestion.",
                    "response_md": (
                        "Yes — JIRA-9999 was filed and the linked ticket exists; "
                        "an alert was triggered for the asset."
                    ),
                    "cited_artifacts": ["evidence_gaps.json"],
                    "cited_fields": [],
                    "citations": [{"artifact": "evidence_gaps.json"}],
                    "missing_evidence": ["linked_ticket_id", "sample_alert_ref"],
                    "warnings": [],
                    "confidence": "moderate",
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = draft_auditor_response(
            question="Show evidence of central log ingestion.",
            evidence_gap={
                "gap_id": "GAP-1",
                "gap_type": "centralized_log_missing",
                "controls": ["AU-6"],
                "recommended_artifact": "central_log_sources.json",
            },
        )
        assert out.source == ReasoningSource.LLM
        assert "JIRA-9999" not in out.response_md
        assert "alert was triggered" not in out.response_md.lower()
        assert MISSING_EVIDENCE_MARK in out.response_md


# ---------------------------------------------------------------------------
# LLM-path success (monkey-patched): structured shape + closed gap_type set
# ---------------------------------------------------------------------------


class TestMonkeyPatchedLlmPath:
    def test_classify_row_llm_path_returns_typed_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")

        def fake_call(**_kwargs: Any) -> str:
            return json.dumps(
                {
                    "source": "llm",
                    "source_item_id": "5",
                    "gap_type": "exploitation_review_missing",
                    "severity": "high",
                    "confidence": "moderate",
                    "rationale": "Row references RA-5(8) exploitation review.",
                    "cited_phrases": ["exploitation review"],
                    "recommended_artifact": "scanner_findings.json",
                    "recommended_validation": "RA5_EXPLOITATION_REVIEW",
                    "poam_required": True,
                    "citations": [
                        {"artifact": "assessment_tracker.csv", "field": "request_text"}
                    ],
                    "missing_evidence": [],
                    "warnings": [],
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = classify_ambiguous_row(
            tracker_row={
                "row_index": 5,
                "request_text": "provide exploitation review evidence for high-criticality vulns",
                "controls": ["RA-5(8)"],
            },
            deterministic_classification={"gap_type": "unknown", "severity": "low"},
        )
        assert out.source == ReasoningSource.LLM
        assert out.gap_type == "exploitation_review_missing"
        assert out.severity == "high"
        assert out.poam_required is True

    def test_classify_row_llm_invalid_gap_type_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LLM cannot escape the closed `GapType` set — Pydantic rejects it
        and the deterministic fallback is returned with a warning."""
        monkeypatch.setenv("AI_API_KEY", "test-key")

        def fake_call(**_kwargs: Any) -> str:
            return json.dumps(
                {
                    "source": "llm",
                    "source_item_id": "10",
                    "gap_type": "totally_invented_gap_type",  # NOT in GapType literal
                    "severity": "high",
                    "confidence": "high",
                    "rationale": "x",
                    "cited_phrases": [],
                    "recommended_artifact": None,
                    "recommended_validation": None,
                    "poam_required": False,
                    "citations": [],
                    "missing_evidence": [],
                    "warnings": [],
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = classify_ambiguous_row(
            tracker_row={"row_index": 10, "request_text": "x"},
            deterministic_classification={"gap_type": "unknown", "severity": "low"},
        )
        # Validation failed → fallback used; gap_type clamped to 'unknown'.
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert out.gap_type == "unknown"
        assert any("schema validation" in w.lower() for w in out.warnings)

    def test_llm_returns_non_json_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")
        monkeypatch.setattr(
            ai_reasoning,
            "_call_openai_compatible",
            lambda **_kw: "I'm sorry, I cannot help with that.",
        )
        out = explain_for_assessor(
            eval_record={"eval_id": "X", "result": "FAIL", "severity": "low"}
        )
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert any("not valid JSON" in w for w in out.warnings)

    def test_llm_returns_empty_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_API_KEY", "test-key")
        monkeypatch.setattr(
            ai_reasoning, "_call_openai_compatible", lambda **_kw: None
        )
        out = explain_for_executive(package_summary={"overall_status": "PASS"})
        assert out.source == ReasoningSource.DETERMINISTIC_FALLBACK
        assert any("LLM unavailable" in w for w in out.warnings)

    def test_conmon_reasonableness_llm_path_supports_openai_compatible_backends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AI_BACKEND", "ollama")
        monkeypatch.setenv("AI_API_BASE", "http://127.0.0.1:11434/v1")
        monkeypatch.setenv("AI_MODEL", "llama3.1")

        def fake_call(**kwargs: Any) -> str:
            assert "conmon_reasonableness" in kwargs["user_message"]
            return json.dumps(
                {
                    "source": "llm",
                    "audience": "assessor",
                    "headline": "ConMon evidence is partial, not reasonable yet.",
                    "body": "Cites conmon_reasonableness.json:summary and does not invent tickets.",
                    "citations": [{"artifact": "conmon_reasonableness.json", "field": "summary"}],
                    "missing_evidence": [],
                    "warnings": [],
                    "referenced_eval_id": "CONMON_REASONABLENESS",
                    "referenced_ksi_id": None,
                    "referenced_finding_id": None,
                }
            )

        monkeypatch.setattr(ai_reasoning, "_call_openai_compatible", fake_call)
        out = explain_conmon_reasonableness(
            conmon_result={"summary": {"obligations": 17}, "obligation_assessments": []}
        )
        assert out.source == ReasoningSource.LLM
        assert out.referenced_eval_id == "CONMON_REASONABLENESS"


# ---------------------------------------------------------------------------
# Allowed gap-type set is the canonical one
# ---------------------------------------------------------------------------


class TestAllowedGapTypes:
    def test_allowed_gap_types_match_core_gap_type_literal(self) -> None:
        from typing import get_args

        from core.models import GapType

        assert set(ALLOWED_GAP_TYPES) == set(get_args(GapType))
        # Sanity: at least the high-value gap types are present.
        for required in (
            "centralized_log_missing",
            "alert_rule_missing",
            "exploitation_review_missing",
            "change_ticket_missing",
            "unknown",
        ):
            assert required in ALLOWED_GAP_TYPES
