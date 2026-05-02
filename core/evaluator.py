"""Orchestrate provider-neutral evaluations over a canonical EvidenceBundle."""

from __future__ import annotations

from pathlib import Path

from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineCorrelationBundle as CorrelationBundle,
    PipelineEvalResult as EvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from core.utils import build_asset_evidence
from evals.agent_approval_gates import eval_agent_approval_gates
from evals.agent_auditability import eval_agent_auditability
from evals.agent_memory_context_safety import eval_agent_memory_context_safety
from evals.agent_permission_scope import eval_agent_permission_scope
from evals.agent_policy_violations import eval_agent_policy_violations
from evals.agent_tool_governance import eval_agent_tool_governance
from evals.alert_instrumentation import eval_alert_instrumentation
from evals.central_log_coverage import eval_central_log_coverage
from evals.change_ticket_linkage import eval_change_ticket_linkage
from evals.event_correlation import eval_event_correlation
from evals.inventory_coverage import eval_inventory_coverage
from evals.poam_status import eval_poam_status
from evals.scanner_scope import eval_scanner_scope
from evals.vulnerability_exploitation_review import eval_vulnerability_exploitation_review


def overall_status(results: list[EvalResult]) -> str:
    if any(r.result == EvalStatus.FAIL for r in results):
        return "FAIL"
    if any(r.result == EvalStatus.PARTIAL for r in results):
        return "PARTIAL"
    return "PASS"


def evidence_chain_dict(results: list[EvalResult]) -> dict[str, str]:
    mapping = {
        "CM8_INVENTORY_RECONCILIATION": "asset_in_inventory",
        "RA5_SCANNER_SCOPE_COVERAGE": "scanner_scope",
        "AU6_CENTRALIZED_LOG_COVERAGE": "central_logging",
        "SI4_ALERT_INSTRUMENTATION": "alert_rule",
        "CROSS_DOMAIN_EVENT_CORRELATION": "event_correlation",
        "RA5_EXPLOITATION_REVIEW": "exploitation_review",
        "CM3_CHANGE_EVIDENCE_LINKAGE": "change_ticket",
        "CA5_POAM_STATUS": "poam_entry",
        "AGENT_TOOL_GOVERNANCE": "agent_tool_governance",
        "AGENT_PERMISSION_SCOPE": "agent_permission_scope",
        "AGENT_MEMORY_CONTEXT_SAFETY": "agent_memory_context_safety",
        "AGENT_APPROVAL_GATES": "agent_approval_gates",
        "AGENT_POLICY_VIOLATIONS": "agent_policy_violations",
        "AGENT_AUDITABILITY": "agent_auditability",
    }
    out: dict[str, str] = {}
    for r in results:
        key = mapping.get(r.eval_id)
        if key:
            out[key] = r.result.value
    return out


def run_evaluations(
    bundle: EvidenceBundle,
    semantic_event: SemanticEvent,
    asset_evidence: AssetEvidence | None = None,
    *,
    output_dir: Path | None = None,
) -> CorrelationBundle:
    if asset_evidence is None:
        asset_evidence = build_asset_evidence(bundle, semantic_event.asset_id)
    results: list[EvalResult] = []
    results.append(eval_inventory_coverage(bundle, semantic_event, asset_evidence))
    results.append(eval_scanner_scope(bundle, semantic_event, asset_evidence))
    results.append(eval_central_log_coverage(bundle, semantic_event, asset_evidence))
    results.append(eval_alert_instrumentation(bundle, semantic_event, asset_evidence))
    results.append(eval_event_correlation(bundle, semantic_event, asset_evidence, output_dir=output_dir))
    results.append(
        eval_vulnerability_exploitation_review(bundle, semantic_event, asset_evidence, output_dir=output_dir)
    )
    results.append(eval_change_ticket_linkage(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_tool_governance(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_permission_scope(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_memory_context_safety(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_approval_gates(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_policy_violations(bundle, semantic_event, asset_evidence))
    results.append(eval_agent_auditability(bundle, semantic_event, asset_evidence))
    results.append(
        eval_poam_status(bundle, semantic_event, asset_evidence, results, output_dir=output_dir)
    )

    chain = evidence_chain_dict(results)
    return CorrelationBundle(
        correlation_id="CORR-001",
        semantic_event=semantic_event,
        asset_evidence=asset_evidence,
        eval_results=results,
        overall_result=overall_status(results),
        evidence_chain=chain,
    )
