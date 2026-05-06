"""Prompt builders for every reasoner in :mod:`ai.reasoning`.

Every prompt is composed of:

1. A **system message** that opens with the binding
   :func:`core.evidence_contract.evidence_contract_markdown` block plus a small
   reasoner-specific role line.
2. A **user message** that supplies the structured input as JSON, and re-states
   the JSON output schema the reasoner must conform to.

Splitting prompts into "system" / "user" parts mirrors the OpenAI
chat-completions contract; the deterministic-fallback path can ignore the
prompts entirely.

The strings here are all `str.format`-free constants — no f-strings against
untrusted input — so a malicious tracker row cannot inject prompt syntax.
Untrusted text is always JSON-encoded into the user message.
"""

from __future__ import annotations

import json
from typing import Any, get_args

from core.evidence_contract import evidence_contract_markdown
from core.models import GapSeverity, GapType


__all__ = [
    "ALLOWED_GAP_TYPES",
    "ALLOWED_GAP_SEVERITIES",
    "JSON_OUTPUT_DIRECTIVE",
    "build_assessor_explanation_messages",
    "build_auditor_response_messages",
    "build_classify_row_messages",
    "build_derivation_trace_messages",
    "build_executive_summary_messages",
    "build_conmon_reasonableness_messages",
    "build_remediation_ticket_messages",
    "build_residual_risk_messages",
    "build_3pao_remediation_messages",
    "redact_secrets_for_prompt",
]


# Canonical allow-lists exposed as constants so the prompts can list them
# verbatim instead of inventing new vocabulary.
ALLOWED_GAP_TYPES: tuple[str, ...] = tuple(get_args(GapType))
ALLOWED_GAP_SEVERITIES: tuple[str, ...] = tuple(get_args(GapSeverity))


# Always appended to user messages so the reasoner emits parseable JSON only.
JSON_OUTPUT_DIRECTIVE = (
    "OUTPUT FORMAT (binding):\n"
    "* Respond with a SINGLE JSON object that exactly matches the schema described above.\n"
    "* No prose before or after the JSON. No backticks. No commentary.\n"
    "* If a required field cannot be derived from the supplied artifacts, set the corresponding\n"
    "  `missing_evidence` entry instead of inventing a value.\n"
)


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------


_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "bearer",
    "authorization",
    "client_secret",
    "access_key",
)


def redact_secrets_for_prompt(obj: Any) -> Any:
    """Strip obvious secret-bearing fields before embedding ``obj`` in a prompt."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if any(frag in str(k).lower() for frag in _SENSITIVE_KEY_FRAGMENTS):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_secrets_for_prompt(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets_for_prompt(x) for x in obj]
    return obj


def _system_preamble(role_line: str) -> str:
    """Every system message starts with the evidence contract + a one-liner role."""
    return (
        f"{role_line}\n\n"
        f"{evidence_contract_markdown()}\n\n"
        "REASONER RULES (binding):\n"
        "* Use ONLY the JSON artifacts the user message provides.\n"
        "* Do NOT invent assets, identifiers, dates, owners, or evidence values.\n"
        "* Missing evidence MUST remain missing — say `**missing evidence**` exactly when it applies.\n"
        "* Cite artifact names and structured field names in every substantive claim.\n"
        "* Distinguish an evidence gap (artifact not provided) from a technical failure (evidence shows a control weakness).\n"
        "* Pass/fail computation, schema validation, dates, and artifact-path existence are NOT yours to compute.\n"
    )


def _payload_block(label: str, payload: Any) -> str:
    """Render a JSON payload as a labeled section the model can quote from."""
    return (
        f"{label} (JSON, redacted where applicable):\n"
        f"{json.dumps(redact_secrets_for_prompt(payload), indent=2, default=str)[:24000]}\n"
    )


# ---------------------------------------------------------------------------
# 1. Classify ambiguous tracker row
# ---------------------------------------------------------------------------


_CLASSIFY_ROW_SYSTEM = _system_preamble(
    "You are an evidence-gap classifier for a FedRAMP assessment tracker."
)


def build_classify_row_messages(
    *,
    tracker_row: dict[str, Any],
    deterministic_classification: dict[str, Any],
) -> tuple[str, str]:
    """Return ``(system, user)`` messages for ambiguous-row classification."""
    user = (
        "Task: Pick the single best `gap_type` for this tracker row from the closed list below.\n"
        "If no type fits, return `unknown` and explain why.\n"
        "\n"
        f"Allowed gap_type values (closed set): {json.dumps(list(ALLOWED_GAP_TYPES))}\n"
        f"Allowed severity values: {json.dumps(list(ALLOWED_GAP_SEVERITIES))}\n"
        "\n"
        + _payload_block("Tracker row", tracker_row)
        + "\n"
        + _payload_block(
            "Deterministic classifier output (was unknown — your job is to refine)",
            deterministic_classification,
        )
        + "\n"
        "Required JSON output schema (RowClassificationReasoning):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "source_item_id": "<tracker row id>",\n'
        '  "gap_type": "<one of the allowed gap_type values>",\n'
        '  "severity": "<one of the allowed severity values>",\n'
        '  "confidence": "low|moderate|high",\n'
        '  "rationale": "<why this gap_type — must reference cited_phrases>",\n'
        '  "cited_phrases": ["<verbatim substring from row>", ...],\n'
        '  "recommended_artifact": "<artifact name or null>",\n'
        '  "recommended_validation": "<validation step or null>",\n'
        '  "poam_required": true|false,\n'
        '  "citations": [{"artifact": "tracker.csv", "field": "request_text", "note": ""}],\n'
        '  "missing_evidence": ["<input field name>", ...],\n'
        '  "warnings": []\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _CLASSIFY_ROW_SYSTEM, user


# ---------------------------------------------------------------------------
# 2. Assessor explanation
# ---------------------------------------------------------------------------


_ASSESSOR_SYSTEM = _system_preamble(
    "You are an expert FedRAMP 20x assessor explaining an evaluation outcome to another assessor."
)


def build_assessor_explanation_messages(
    *,
    eval_record: dict[str, Any],
    related_evidence: dict[str, Any] | None = None,
    fedramp20x_context: dict[str, Any] | None = None,
) -> tuple[str, str]:
    user = (
        "Task: Write a precise assessor-facing explanation of the supplied eval row.\n"
        "Cover: what the criterion is, what the result means, which artifact fields proved it,\n"
        "and what closure evidence is still required.\n"
        "\n"
        + _payload_block("Eval row (eval_results.json)", eval_record)
        + (
            _payload_block("Related evidence", related_evidence)
            if related_evidence
            else ""
        )
        + (
            _payload_block("FedRAMP 20x context (package slice)", fedramp20x_context)
            if fedramp20x_context
            else ""
        )
        + "\n"
        "Required JSON output schema (ExplanationResponse):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "audience": "assessor",\n'
        '  "headline": "<one-line summary>",\n'
        '  "body": "<markdown body grounded in citations>",\n'
        '  "citations": [{"artifact": "eval_results.json", "field": "evaluations[i].gap"}],\n'
        '  "missing_evidence": ["<field>", ...],\n'
        '  "warnings": [],\n'
        '  "referenced_eval_id": "<eval_id or null>",\n'
        '  "referenced_ksi_id": null,\n'
        '  "referenced_finding_id": null\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _ASSESSOR_SYSTEM, user


# ---------------------------------------------------------------------------
# 3. Executive summary
# ---------------------------------------------------------------------------


_EXEC_SYSTEM = _system_preamble(
    "You are summarizing a FedRAMP 20x package for a non-technical executive audience."
)


def build_executive_summary_messages(
    *,
    package_summary: dict[str, Any],
    fail_partial_findings: list[dict[str, Any]] | None = None,
    open_poam: list[dict[str, Any]] | None = None,
) -> tuple[str, str]:
    user = (
        "Task: Write a concise readiness summary for an executive sponsor.\n"
        "Focus on overall posture, not implementation details. Avoid jargon. Cite the package fields.\n"
        "\n"
        + _payload_block("Package summary (fedramp20x-package.json slice)", package_summary)
        + (
            _payload_block("Open FAIL/PARTIAL findings", fail_partial_findings or [])
        )
        + (
            _payload_block("Open POA&M items", open_poam or [])
        )
        + "\n"
        "Required JSON output schema (ExplanationResponse):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "audience": "executive",\n'
        '  "headline": "<one-line readiness statement>",\n'
        '  "body": "<short markdown body>",\n'
        '  "citations": [{"artifact": "fedramp20x-package.json", "field": "summary.<...>"}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": []\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _EXEC_SYSTEM, user


_CONMON_REASONABLENESS_SYSTEM = _system_preamble(
    "You are a 3PAO senior assessor reviewing a FedRAMP ConMon reasonableness report."
)


def build_conmon_reasonableness_messages(
    *,
    conmon_result: dict[str, Any],
) -> tuple[str, str]:
    user = (
        "Task: Explain whether the ConMon evidence posture is reasonable for 3PAO review. "
        "Use the supplied `conmon_reasonableness.json` only. You may prioritize obligations and "
        "explain what AWS/CloudTrail, CloudWatch/Splunk/Wazuh, scanner exports, and "
        "Smartsheet/Jira/ServiceNow evidence must prove, but you must not mark missing evidence as passing.\n"
        "\n"
        + _payload_block("ConMon reasonableness result", conmon_result)
        + "\n"
        "Required JSON output schema (ExplanationResponse):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "audience": "assessor",\n'
        '  "headline": "<short 3PAO reasonableness conclusion>",\n'
        '  "body": "<markdown body grounded only in conmon_reasonableness.json>",\n'
        '  "citations": [{"artifact": "conmon_reasonableness.json", "field": "summary", "note": ""}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": [],\n'
        '  "referenced_eval_id": "CONMON_REASONABLENESS",\n'
        '  "referenced_ksi_id": null,\n'
        '  "referenced_finding_id": null\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _CONMON_REASONABLENESS_SYSTEM, user


# ---------------------------------------------------------------------------
# 4. AO residual risk
# ---------------------------------------------------------------------------


_AO_SYSTEM = _system_preamble(
    "You are framing residual risk for an Authorizing Official (AO) decision."
)


def build_residual_risk_messages(
    *,
    finding: dict[str, Any],
    poam: dict[str, Any] | None = None,
    related_ksi: dict[str, Any] | None = None,
) -> tuple[str, str]:
    user = (
        "Task: Frame residual risk for an AO. Use risk-acceptance language. Cite the finding and POA&M ids.\n"
        "Do not invent acceptance — only describe the documented posture.\n"
        "\n"
        + _payload_block("Finding (fedramp20x-package.json findings[])", finding)
        + (_payload_block("Linked POA&M item", poam) if poam else "")
        + (_payload_block("Related KSI", related_ksi) if related_ksi else "")
        + "\n"
        "Required JSON output schema (ExplanationResponse):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "audience": "ao",\n'
        '  "headline": "<one-line residual risk statement>",\n'
        '  "body": "<markdown body>",\n'
        '  "citations": [{"artifact": "fedramp20x-package.json", "field": "findings[i].finding_id"}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": [],\n'
        '  "referenced_finding_id": "<finding_id or null>",\n'
        '  "referenced_ksi_id": "<ksi_id or null>"\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _AO_SYSTEM, user


# ---------------------------------------------------------------------------
# 5. Derivation trace narration
# ---------------------------------------------------------------------------


_TRACE_SYSTEM = _system_preamble(
    "You are narrating an autonomous agent run trace in plain language for a human reviewer."
)


def build_derivation_trace_messages(
    *,
    trace: dict[str, Any],
) -> tuple[str, str]:
    user = (
        "Task: Walk the workflow trace step by step in plain language.\n"
        "For each task explain WHAT it consumed, WHAT it produced, and HOW its policy decision was reached.\n"
        "Do NOT claim a task succeeded if its `status` is not `success`.\n"
        "\n"
        + _payload_block("agent_run_trace.json (slice)", trace)
        + "\n"
        "Required JSON output schema (ExplanationResponse):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "audience": "derivation_trace",\n'
        '  "headline": "<one-line description of overall_status>",\n'
        '  "body": "<markdown body, one bullet per task>",\n'
        '  "citations": [{"artifact": "agent_run_trace.json", "field": "tasks[i]"}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": []\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _TRACE_SYSTEM, user


# ---------------------------------------------------------------------------
# 6. Remediation ticket draft
# ---------------------------------------------------------------------------


_REMEDIATION_SYSTEM = _system_preamble(
    "You are drafting a LOCAL remediation ticket. The draft is NOT submitted to any external system."
)


def build_remediation_ticket_messages(
    *,
    finding: dict[str, Any],
    eval_record: dict[str, Any] | None = None,
) -> tuple[str, str]:
    user = (
        "Task: Draft a remediation ticket for the supplied finding.\n"
        "Title must be <= 100 chars, action-oriented, and include the finding_id.\n"
        "Acceptance criteria must be deterministic — the reviewer can verify each one without\n"
        "asking the original finder a follow-up question.\n"
        "\n"
        + _payload_block("Finding", finding)
        + (
            _payload_block("Originating eval row", eval_record)
            if eval_record
            else ""
        )
        + "\n"
        "Required JSON output schema (RemediationTicketDraft):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "draft_ticket_id": "DRAFT-TICKET-<finding_id>",\n'
        '  "title": "<<=100 chars>",\n'
        '  "description_md": "<markdown body>",\n'
        '  "severity": "low|moderate|high|critical|informational",\n'
        '  "controls": ["<control id>", ...],\n'
        '  "affected_artifacts": ["eval_results.json", ...],\n'
        '  "acceptance_criteria": ["<deterministic criterion>", ...],\n'
        '  "citations": [{"artifact": "fedramp20x-package.json", "field": "findings[i].finding_id"}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": []\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _REMEDIATION_SYSTEM, user


# ---------------------------------------------------------------------------
# 7. Auditor-response draft
# ---------------------------------------------------------------------------


_AUDITOR_SYSTEM = _system_preamble(
    "You are drafting a LOCAL response to an auditor question. The draft is NOT sent to the auditor."
)


def build_auditor_response_messages(
    *,
    question: str,
    evidence_gap: dict[str, Any] | None = None,
    eval_record: dict[str, Any] | None = None,
    related_artifacts: dict[str, Any] | None = None,
) -> tuple[str, str]:
    user = (
        "Task: Draft a precise, evidence-bounded response to the auditor's question.\n"
        "Cite every artifact and field by name. If evidence does not exist in the inputs,\n"
        "state `**missing evidence**` rather than improvising.\n"
        "\n"
        + _payload_block("Auditor question", {"question": question})
        + (_payload_block("EvidenceGap (if any)", evidence_gap) if evidence_gap else "")
        + (_payload_block("Eval row (if any)", eval_record) if eval_record else "")
        + (
            _payload_block("Related artifacts", related_artifacts)
            if related_artifacts
            else ""
        )
        + "\n"
        "Required JSON output schema (AuditorResponseDraft):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "question": "<echo of the question>",\n'
        '  "response_md": "<markdown body grounded in citations>",\n'
        '  "cited_artifacts": ["<artifact name>", ...],\n'
        '  "cited_fields": ["<field path>", ...],\n'
        '  "citations": [{"artifact": "...", "field": "..."}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": [],\n'
        '  "confidence": "low|moderate|high"\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _AUDITOR_SYSTEM, user


# ---------------------------------------------------------------------------
# 8. 3PAO Remediation Evaluation
# ---------------------------------------------------------------------------


_THREE_PAO_SYSTEM = _system_preamble(
    "You are a senior FedRAMP Third-Party Assessment Organization (3PAO) assessor working a Security "
    "Assessment Plan (SAP) / evidence-tracker row (often mirrored in ConMon). You align expectations with "
    "NIST SP 800-53 controls as cited on the row, FedRAMP authorization practice (including reasonable "
    "evidence and SAR-ready documentation), and—when provided—a FedRAMP 20x Key Security Indicator (KSI) "
    "context block. Classify each row mentally as one or more of: package/policy documentation; "
    "system-generated operational evidence; vulnerability / pen-test logistics; contingency / IR test "
    "artifacts; IAM / personnel; boundary / crypto; or continuous monitoring sampling. Do not invent "
    "artifacts that are not described in the gap payload; use `missing_evidence` for items the CSP must "
    "still produce."
)


def build_3pao_remediation_messages(
    *,
    evidence_gap: dict[str, Any],
    ksi_context: str | None = None,
    related_artifacts: dict[str, Any] | None = None,
) -> tuple[str, str]:
    ksi_block = (
        ("\n" + ksi_context.strip() + "\n")
        if (ksi_context and str(ksi_context).strip())
        else ""
    )
    user = (
        "Task: Evaluate this assessment-tracker evidence gap as a 3PAO would before SAR / 20x package "
        "review — using the **reasonable-person** standard (would a prudent assessor accept the CSP's "
        "latest position without reopening the control?).\n"
        "\n"
        "Workflow (follow in order; reflect it in `remediation_plan_md` when the row is not yet closed):\n"
        "A. **Row archetype** — SAP kickoff vs core control evidence vs pen-test engagement logistics vs "
        "ConMon sample vs policy/SSP attachment vs other.\n"
        "B. **Decompose the ask** — extract every explicit sub-bullet (i)(ii)(iii)… from the request text "
        "and from the latest unresolved assessor questions in the comment thread.\n"
        "C. **Control + KSI linkage** — interpret listed controls; use the KSI context block (if present) "
        "as additional framing for *types* of evidence maturity — not as a substitute for the control text.\n"
        "D. **Thread resolution** — read assessor↔CSP comments chronologically; state what remains open "
        "after the CSP's last reply.\n"
        "E. **Reasonable test** — decide if remaining gaps are clerical, evidentiary (missing primary/system-"
        "generated proof), or scope disputes; set `reasonable_test_passed` true only if the assessor's "
        "stated requirements appear fully met by the latest CSP stance **or** defensibly N/A with documented "
        "rationale.\n"
        "F. **Closure path** — if not passed, give concrete remediation: exact artifact classes, who should "
        "sign/approve, what system export to attach, and how a reviewer would verify (no generic 'provide "
        "evidence' only).\n"
        "\n"
        "If `poam_required` is true in the gap, note when a POA&M milestone or FedRAMP deviation request "
        "(FP/RA/OR/vendor dependency) may be required instead of verbal closure.\n"
        "If `related_artifacts` are provided, evaluate whether they are sufficient, authoritative, current, "
        "and mapped to each sub-requirement; do not pass the reasonable test merely because a ticket or "
        "filename exists.\n"
        + ksi_block
        + _payload_block("Evidence Gap", evidence_gap)
        + (_payload_block("Related artifacts", related_artifacts) if related_artifacts else "")
        + "\n"
        "Required JSON output schema (ThreePaoRemediationEvaluation):\n"
        "{\n"
        '  "source": "llm",\n'
        '  "gap_id": "<echo gap_id>",\n'
        '  "recommendation": "<1-2 sentence recommendation>",\n'
        '  "remediation_plan_md": "<markdown step-by-step plan based on NIST/FedRAMP requirements>",\n'
        '  "reasonable_test_passed": true|false,\n'
        '  "citations": [{"artifact": "evidence_gaps.json", "field": "gap_id"}],\n'
        '  "artifact_sufficiency": [{"requirement": "<sub-requirement>", "status": "pass|fail|unknown", "evidence": "<provided artifact basis or missing evidence>", "remediation": "<closure step or null>"}],\n'
        '  "missing_evidence": [],\n'
        '  "warnings": []\n'
        "}\n\n"
        + JSON_OUTPUT_DIRECTIVE
    )
    return _THREE_PAO_SYSTEM, user
