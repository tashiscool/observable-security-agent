"""Shared helpers for AI agent behavior telemetry evaluations."""

from __future__ import annotations

import json
import re
from pathlib import Path
from core.agent_models import AgentAssessmentBundle, AgentIdentity, AgentToolCall, agent_assessment_bundle_from_json
from core.models import EvalResult
from core.pipeline_models import EvalStatus, PipelineEvalResult, PipelineEvidenceBundle

# --- Control / KSI-oriented mappings (NIST 800-53 style; public references only) ---

AGENT_TOOL_GOVERNANCE_CONTROLS = ["AC-6", "CM-10", "CM-11", "SA-9"]
AGENT_PERMISSION_SCOPE_CONTROLS = ["AC-2", "AC-3", "AC-6", "IA-5"]
AGENT_MEMORY_CONTEXT_SAFETY_CONTROLS = ["SC-28", "AC-4", "AU-9", "SI-12"]
AGENT_APPROVAL_GATES_CONTROLS = ["CM-3", "CM-5", "CA-7", "SA-9"]
AGENT_POLICY_VIOLATIONS_CONTROLS = ["IR-4", "SI-4", "AC-2", "AC-6"]
AGENT_AUDITABILITY_CONTROLS = ["AU-2", "AU-3", "AU-6", "AU-9"]

_DESTRUCTIVE_ACTION_MARKERS = (
    "delete",
    "destroy",
    "revoke",
    "mutate",
    "putrole",
    "attachpolicy",
    "createaccesskey",
    "createlogin",
)


def _load_json_list_file(path: Path) -> list:
    """Load a JSON file that is either a bare array or a single-key object whose value is an array."""
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def load_agent_assessment_bundle(source_root: Path) -> AgentAssessmentBundle | None:
    """
    Load agent telemetry from the fixture / evidence root.

    Precedence:
    1. ``agent_security/agent_assessment.json`` (monolithic bundle).
    2. Split layout: ``agent_identities.json`` plus optional ``agent_tool_calls.json``,
       ``agent_memory_events.json``, ``agent_policy_violations.json`` at the scenario root.
    """
    legacy = source_root / "agent_security" / "agent_assessment.json"
    if legacy.is_file():
        return agent_assessment_bundle_from_json(legacy.read_text(encoding="utf-8"))

    split_anchor = source_root / "agent_identities.json"
    if not split_anchor.is_file():
        return None

    payload = {
        "agent_identities": _load_json_list_file(split_anchor),
        "tool_calls": _load_json_list_file(source_root / "agent_tool_calls.json"),
        "memory_events": _load_json_list_file(source_root / "agent_memory_events.json"),
        "policy_violations": _load_json_list_file(source_root / "agent_policy_violations.json"),
    }
    return AgentAssessmentBundle.model_validate(payload)


def canonical_to_pipeline(er: EvalResult) -> PipelineEvalResult:
    status = EvalStatus.PASS
    if er.result == "FAIL":
        status = EvalStatus.FAIL
    elif er.result in ("PARTIAL", "NOT_APPLICABLE"):
        status = EvalStatus.PARTIAL
    gap = "; ".join(er.gaps) if er.gaps else er.summary
    action = "; ".join(er.recommended_actions) if er.recommended_actions else ""
    return PipelineEvalResult(
        eval_id=er.eval_id,
        control_refs=er.controls,
        result=status,
        evidence=er.evidence,
        gap=gap,
        recommended_action=action,
        machine={
            "severity": er.severity,
            "summary": er.summary,
            "name": er.name,
            "gaps": er.gaps,
            "affected_assets": er.affected_assets,
        },
    )


def skipped_no_agent_data(
    *,
    eval_id: str,
    name: str,
    controls: list[str],
    detail: str = "No agent_security/agent_assessment.json next to this scenario; agent telemetry eval skipped.",
) -> PipelineEvalResult:
    return PipelineEvalResult(
        eval_id=eval_id,
        control_refs=controls,
        result=EvalStatus.PASS,
        evidence=[detail],
        gap="",
        recommended_action="",
        machine={"severity": "low", "summary": detail, "name": name, "skipped": True},
    )


def _identity_map(ab: AgentAssessmentBundle) -> dict[str, object]:
    return {i.agent_id: i for i in ab.agent_identities}


def _tool_allowed_for_identity(tc: AgentToolCall, ident: object) -> tuple[bool, str | None]:
    if not isinstance(ident, AgentIdentity):
        return False, f"No registered identity for agent_id {tc.agent_id!r}"
    if tc.tool_name not in ident.allowed_tools:
        return False, f"Tool `{tc.tool_name}` not in allowed_tools for {tc.agent_id}"
    if ident.allowed_actions and tc.action not in ident.allowed_actions:
        if not any(a.lower() in tc.action.lower() for a in ident.allowed_actions):
            return False, f"Action `{tc.action}` not covered by allowed_actions for {tc.agent_id}"
    if tc.target_resource and ident.allowed_data_scopes:
        tr = tc.target_resource
        if not any(tr.startswith(s) or s in tr for s in ident.allowed_data_scopes):
            return False, f"target_resource `{tr}` outside allowed_data_scopes for {tc.agent_id}"
    if tc.risk_level in ("high", "critical") and tc.policy_decision == "unknown":
        return False, f"High/critical tool call with policy_decision=unknown ({tc.call_id})"
    return True, None


def run_agent_tool_governance(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_TOOL_GOVERNANCE"
    name = "Agent tool governance"
    controls = list(AGENT_TOOL_GOVERNANCE_CONTROLS)
    idm = _identity_map(ab)
    evidence: list[str] = []
    gaps: list[str] = []
    if not ab.tool_calls:
        evidence.append("No tool_calls recorded; nothing to validate against allow lists.")
        return EvalResult(
            eval_id=eval_id,
            name=name,
            result="PASS",
            controls=controls,
            severity="low",
            summary="No agent tool invocations in bundle.",
            evidence=evidence,
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )
    for tc in ab.tool_calls:
        ident_obj = idm.get(tc.agent_id)
        ok, msg = _tool_allowed_for_identity(tc, ident_obj)
        if not ok and msg:
            gaps.append(msg)
            evidence.append(msg)
    outcome = "FAIL" if gaps else "PASS"
    summary = (
        "Agent tool calls respect allow lists and policy decisions."
        if outcome == "PASS"
        else "Agent tool governance failed: disallowed tool, action, scope, or unknown high-risk policy."
    )
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity="high" if outcome == "FAIL" else "low",
        summary=summary,
        evidence=evidence or [summary],
        gaps=gaps,
        affected_assets=[],
        recommended_actions=(
            []
            if outcome == "PASS"
            else [
                "Restrict tool allow list to least privilege.",
                "Attach policy_decision evidence for high-risk calls.",
                "Map tool calls to change records where applicable.",
            ]
        ),
    )


def run_agent_permission_scope(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_PERMISSION_SCOPE"
    name = "Agent permission scope"
    controls = list(AGENT_PERMISSION_SCOPE_CONTROLS)
    gaps: list[str] = []
    for ident in ab.agent_identities:
        blob = " ".join(ident.allowed_actions) + " " + " ".join(ident.allowed_tools)
        if "*" in blob or "*:*" in blob:
            gaps.append(f"Wildcard capability detected for agent {ident.agent_id}.")
        cr = (ident.credentials_ref or "").lower()
        if re.search(r"\b(admin|root|superuser|human_user|breakglass)\b", cr):
            gaps.append(f"Agent {ident.agent_id} references human/admin-style credentials_ref.")
        if ident.environment == "prod" and not ident.allowed_data_scopes:
            gaps.append(f"Agent {ident.agent_id} marked prod with empty allowed_data_scopes.")
    for tc in ab.tool_calls:
        ident = _identity_map(ab).get(tc.agent_id)
        if (
            isinstance(ident, AgentIdentity)
            and ident.environment != "prod"
            and tc.target_resource
            and "prod" in tc.target_resource.lower()
            and ident.allowed_data_scopes
            and not any(tc.target_resource.startswith(s) for s in ident.allowed_data_scopes)
        ):
            gaps.append(f"Non-prod agent {tc.agent_id} touched prod-shaped resource {tc.target_resource}.")
    outcome = "FAIL" if gaps else "PASS"
    summary = "Agent permissions match assigned workflow." if outcome == "PASS" else "Agent permission scope violations detected."
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity="high" if outcome == "FAIL" else "low",
        summary=summary,
        evidence=gaps or [summary],
        gaps=gaps,
        affected_assets=[],
        recommended_actions=[] if outcome == "PASS" else ["Tighten IAM / data scopes.", "Use workload identity instead of long-lived admin keys."],
    )


def run_agent_memory_context_safety(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_MEMORY_CONTEXT_SAFETY"
    name = "Agent memory context safety"
    controls = list(AGENT_MEMORY_CONTEXT_SAFETY_CONTROLS)
    gaps: list[str] = []
    for me in ab.memory_events:
        if me.memory_type in ("long_term", "vector") and me.action == "write" and me.sensitivity in ("pii", "secret"):
            if me.policy_decision != "blocked":
                gaps.append(
                    f"Sensitive write to {me.memory_type} memory ({me.memory_event_id}) without explicit block policy.",
                )
        if me.memory_type == "external_context":
            src = me.source.lower()
            if "trusted:" not in src and "untrusted" not in src:
                gaps.append(
                    f"External context {me.memory_event_id} lacks trusted/untrusted labeling in source.",
                )
    # Influence without trace: retrieve then tool call with empty raw_ref (same minute heuristic)
    mem_sorted = sorted(ab.memory_events, key=lambda m: m.timestamp)
    tools_sorted = sorted(ab.tool_calls, key=lambda t: t.timestamp)
    for tc in tools_sorted:
        if tc.raw_ref and str(tc.raw_ref).strip():
            continue
        for me in mem_sorted:
            if me.action == "retrieve" and me.timestamp <= tc.timestamp and (tc.timestamp - me.timestamp).total_seconds() < 120:
                gaps.append(
                    f"Tool call {tc.call_id} has empty raw_ref shortly after memory retrieve {me.memory_event_id} (traceability gap).",
                )
                break
    outcome = "FAIL" if gaps else "PASS"
    summary = "Memory handling avoids improper sensitive retention." if outcome == "PASS" else "Memory / context safety issues detected."
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity="high" if outcome == "FAIL" else "low",
        summary=summary,
        evidence=gaps or [summary],
        gaps=gaps,
        affected_assets=[],
        recommended_actions=[] if outcome == "PASS" else ["Label external context; block sensitive long-term writes.", "Require raw_ref on tool calls after RAG retrieve."],
    )


def run_agent_approval_gates(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_APPROVAL_GATES"
    name = "Agent approval gates"
    controls = list(AGENT_APPROVAL_GATES_CONTROLS)
    gaps: list[str] = []
    for tc in ab.tool_calls:
        if tc.approval_gap_detectable:
            gaps.append(f"Tool call {tc.call_id} requires approval but approval_status is missing.")
        al = tc.action.lower()
        if any(m in al for m in _DESTRUCTIVE_ACTION_MARKERS):
            if tc.approval_status not in ("approved",) and tc.policy_decision == "allowed":
                gaps.append(f"Destructive-class action `{tc.action}` allowed without recorded approval ({tc.call_id}).")
        if "remediat" in al and not (tc.raw_ref and str(tc.raw_ref).strip()):
            gaps.append(f"Remediation-class action without policy/raw_ref evidence ({tc.call_id}).")
    outcome = "FAIL" if gaps else "PASS"
    summary = "Risky actions are approval-gated." if outcome == "PASS" else "Approval gate violations detected."
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity="high" if outcome == "FAIL" else "low",
        summary=summary,
        evidence=gaps or [summary],
        gaps=gaps,
        affected_assets=[],
        recommended_actions=[] if outcome == "PASS" else ["Enforce approval workflow for destructive tools.", "Record policy_ref on remediation actions."],
    )


def run_agent_policy_violations(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_POLICY_VIOLATIONS"
    name = "Agent policy violations"
    controls = list(AGENT_POLICY_VIOLATIONS_CONTROLS)
    if not ab.policy_violations:
        return EvalResult(
            eval_id=eval_id,
            name=name,
            result="PASS",
            controls=controls,
            severity="low",
            summary="No agent policy violations recorded.",
            evidence=["policy_violations[] is empty."],
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )
    worst = "info"
    order = ("info", "low", "medium", "high", "critical")
    gaps: list[str] = []
    for v in ab.policy_violations:
        gaps.append(f"{v.violation_type} ({v.severity}): {v.evidence[:200]}")
        if order.index(v.severity) > order.index(worst):
            worst = v.severity
    if worst == "critical" or any(
        v.violation_type
        in (
            "prompt_injection_suspected",
            "credential_misuse",
            "privilege_escalation_attempt",
            "approval_bypass",
        )
        for v in ab.policy_violations
    ):
        outcome = "FAIL"
    elif worst in ("high",):
        outcome = "FAIL"
    elif worst == "medium":
        outcome = "PARTIAL"
    else:
        outcome = "PASS"
    summary = {
        "FAIL": "Serious agent policy violations require response.",
        "PARTIAL": "Medium-severity agent violations need review.",
        "PASS": "Only low-severity or informational violation records.",
    }[outcome]
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity=worst if worst != "info" else "low",
        summary=summary,
        evidence=gaps,
        gaps=gaps if outcome != "PASS" else [],
        affected_assets=[],
        recommended_actions=[] if outcome == "PASS" else ["Triage linked tickets; revoke sessions as needed.", "Retrain guardrails for detected violation classes."],
    )


def run_agent_auditability(ab: AgentAssessmentBundle) -> EvalResult:
    eval_id = "AGENT_AUDITABILITY"
    name = "Agent auditability"
    controls = list(AGENT_AUDITABILITY_CONTROLS)
    structural: list[str] = []
    if ab.agent_identities and not ab.tool_calls:
        structural.append("Agent identities registered but no tool_calls[] audit log.")
    if not ab.agent_identities and ab.tool_calls:
        structural.append("Tool calls present without registered agent identities.")

    detail_gaps: list[str] = []
    flagged_calls = 0
    for tc in ab.tool_calls:
        issues = 0
        if tc.policy_decision == "unknown":
            detail_gaps.append(f"Tool call {tc.call_id} has policy_decision=unknown.")
            issues += 1
        if not (tc.raw_ref and str(tc.raw_ref).strip()):
            detail_gaps.append(f"Tool call {tc.call_id} missing raw_ref (raw evidence reference).")
            issues += 1
        if issues:
            flagged_calls += 1

    n_calls = len(ab.tool_calls)
    if structural:
        outcome: str = "FAIL"
        gaps = structural + detail_gaps
    elif n_calls == 0 and not ab.agent_identities:
        outcome = "PASS"
        gaps = []
    elif n_calls == 0:
        outcome = "PASS"
        gaps = []
    elif flagged_calls == 0:
        outcome = "PASS"
        gaps = []
    elif flagged_calls == n_calls:
        outcome = "FAIL"
        gaps = detail_gaps
    else:
        outcome = "PARTIAL"
        gaps = detail_gaps

    if outcome == "PASS":
        summary = "Agent decisions are traceable end-to-end."
        severity = "low"
        actions: list[str] = []
    elif outcome == "PARTIAL":
        summary = "Some agent tool calls lack full audit metadata (policy decision or raw evidence ref)."
        severity = "moderate"
        actions = [
            "Backfill raw_ref on all tool invocations tied to customer workflows.",
            "Ensure policy_decision is populated before execution for high-risk tools.",
        ]
    else:
        summary = "Agent auditability gaps detected."
        severity = "high"
        actions = [
            "Emit structured tool audit with policy_decision and raw_ref.",
            "Register all agents in agent_identities[].",
        ]

    evidence = gaps if gaps else [summary]
    return EvalResult(
        eval_id=eval_id,
        name=name,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity=severity,  # type: ignore[arg-type]
        summary=summary,
        evidence=evidence,
        gaps=gaps,
        affected_assets=[],
        recommended_actions=actions,
    )


def run_agent_eval(
    bundle: PipelineEvidenceBundle,
    *,
    runner,
    eval_id: str,
    name: str,
    controls: list[str],
) -> PipelineEvalResult:
    ab = load_agent_assessment_bundle(bundle.source_root)
    if ab is None:
        return skipped_no_agent_data(eval_id=eval_id, name=name, controls=controls)
    return canonical_to_pipeline(runner(ab))
