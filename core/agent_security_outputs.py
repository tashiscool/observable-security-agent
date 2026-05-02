"""Agent-security-only reports emitted when ``agent.py assess --include-agent-security`` is used."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.agent_models import AgentAssessmentBundle, AgentPolicyViolation, AgentToolCall
from core.evaluator import overall_status
from core.poam import build_poam_generation, write_poam_csv_file
from core.pipeline_models import PipelineCorrelationBundle, PipelineEvalResult
from core.report_writer import build_eval_results_document

AGENT_EVAL_IDS: frozenset[str] = frozenset(
    {
        "AGENT_TOOL_GOVERNANCE",
        "AGENT_PERMISSION_SCOPE",
        "AGENT_MEMORY_CONTEXT_SAFETY",
        "AGENT_APPROVAL_GATES",
        "AGENT_POLICY_VIOLATIONS",
        "AGENT_AUDITABILITY",
    },
)


def agent_eval_results_from_correlation(bundle: PipelineCorrelationBundle) -> list[PipelineEvalResult]:
    return [r for r in bundle.eval_results if r.eval_id in AGENT_EVAL_IDS]


def _agent_risk_report_markdown(
    full_bundle: PipelineCorrelationBundle,
    agent_subset: list[PipelineEvalResult],
    agent_assessment: AgentAssessmentBundle | None,
) -> str:
    lines: list[str] = [
        "# Agentic risk assessment (telemetry slice)",
        "",
        f"Primary semantic event: `{full_bundle.semantic_event.event_type}` on asset `{full_bundle.semantic_event.asset_id}`.",
        "",
        "## Agent governance evaluations",
        "",
    ]
    for r in agent_subset:
        lines.append(f"- **{r.eval_id}** — {r.result.value}: {(r.gap or '').strip() or (r.machine or {}).get('summary', '')}")
    lines.extend(["", "## Telemetry highlights", ""])
    if agent_assessment is None:
        lines.append("*No agent assessment bundle loaded.*")
    else:
        lines.append(f"- Registered agents: {len(agent_assessment.agent_identities)}")
        lines.append(f"- Tool invocations logged: {len(agent_assessment.tool_calls)}")
        lines.append(f"- Memory events: {len(agent_assessment.memory_events)}")
        lines.append(f"- Policy violations recorded: {len(agent_assessment.policy_violations)}")
        for v in agent_assessment.policy_violations:
            ev = v.evidence
            tail = "…" if len(ev) > 160 else ""
            lines.append(f"  - `{v.violation_id}` ({v.violation_type}, {v.severity}): {ev[:160]}{tail}")
    lines.extend(["", "## Recommended follow-up", "", "- Tighten tool allow lists and enforce runtime policy before invocation.", "- Add SIEM correlation for blocked high-privilege tool attempts.", "- Label untrusted ticket/RAG context; block sensitive long-term retention.", ""])
    return "\n".join(lines)


def _hunt_query_for_violation(v: AgentPolicyViolation) -> str:
    if v.violation_type == "prompt_injection_suspected":
        return 'index=support_tickets "ignore previous instructions" OR "disregard prior" | stats count by ticket_id'
    if v.violation_type == "unauthorized_tool_use":
        return 'index=agent_audit tool_name="cloud_admin_tool" policy_decision="blocked" | stats count by agent_id'
    return f'index=agent_audit violation_type="{v.violation_type}" agent_id="{v.agent_id}"'


def _hunt_query_for_tool(tc: AgentToolCall) -> str:
    return (
        f'index=agent_audit call_id="{tc.call_id}" OR tool_name="{tc.tool_name}" '
        f'| eval blocked=if(policy_decision=="blocked",1,0) | stats sum(blocked) by agent_id'
    )


def _agent_threat_hunt_payload(
    agent_assessment: AgentAssessmentBundle | None,
    agent_subset: list[PipelineEvalResult],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    if agent_assessment:
        for v in agent_assessment.policy_violations:
            findings.append(
                {
                    "finding_id": v.violation_id,
                    "kind": "policy_violation",
                    "violation_type": v.violation_type,
                    "severity": v.severity,
                    "agent_id": v.agent_id,
                    "evidence": v.evidence,
                    "linked_ticket_id": v.linked_ticket_id,
                    "recommended_action": v.recommended_action,
                    "suggested_hunt_query": _hunt_query_for_violation(v),
                }
            )
        for tc in agent_assessment.tool_calls:
            if tc.policy_decision == "blocked" or tc.risk_level in ("high", "critical"):
                findings.append(
                    {
                        "finding_id": f"hunt-tool-{tc.call_id}",
                        "kind": "tool_invocation",
                        "tool_name": tc.tool_name,
                        "policy_decision": tc.policy_decision,
                        "risk_level": tc.risk_level,
                        "agent_id": tc.agent_id,
                        "target_resource": tc.target_resource,
                        "suggested_hunt_query": _hunt_query_for_tool(tc),
                    }
                )
    for r in agent_subset:
        if r.result.value in ("FAIL", "PARTIAL"):
            findings.append(
                {
                    "finding_id": f"hunt-eval-{r.eval_id}",
                    "kind": "eval_gap",
                    "eval_id": r.eval_id,
                    "result": r.result.value,
                    "summary": (r.machine or {}).get("summary", r.gap),
                    "suggested_hunt_query": f'index=agent_governance eval_id="{r.eval_id}" result!=PASS',
                }
            )
    return {
        "schema_version": "1.0",
        "source": "observable-security-agent assess --include-agent-security",
        "findings": findings,
    }


def write_agent_security_bundle(
    output_dir: Path,
    *,
    full_bundle: PipelineCorrelationBundle,
    agent_assessment: AgentAssessmentBundle | None,
) -> list[str]:
    """Write agent-focused artifacts; returns absolute paths of files written."""
    subset = agent_eval_results_from_correlation(full_bundle)
    out_dir = output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    mini = PipelineCorrelationBundle(
        correlation_id=f"{full_bundle.correlation_id}-AGENT",
        semantic_event=full_bundle.semantic_event,
        asset_evidence=full_bundle.asset_evidence,
        eval_results=subset,
        overall_result=overall_status(subset),
        evidence_chain={r.eval_id: r.result.value for r in subset},
    )
    doc = build_eval_results_document(mini, assessment=None, correlations_data=None)
    p_eval = out_dir / "agent_eval_results.json"
    p_eval.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    written.append(str(p_eval))

    p_md = out_dir / "agent_risk_report.md"
    p_md.write_text(_agent_risk_report_markdown(full_bundle, subset, agent_assessment), encoding="utf-8")
    written.append(str(p_md))

    p_hunt = out_dir / "agent_threat_hunt_findings.json"
    p_hunt.write_text(json.dumps(_agent_threat_hunt_payload(agent_assessment, subset), indent=2, default=str), encoding="utf-8")
    written.append(str(p_hunt))

    rows, _stats = build_poam_generation(
        subset,
        full_bundle.semantic_event,
        existing_poam_items=[],
        seed_poam_rows=[],
        reference_date=None,
    )
    p_poam = out_dir / "agent_poam.csv"
    write_poam_csv_file(p_poam, rows)
    written.append(str(p_poam))

    return written


__all__ = [
    "AGENT_EVAL_IDS",
    "agent_eval_results_from_correlation",
    "write_agent_security_bundle",
]
