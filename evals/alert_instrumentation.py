"""SI-4 alert instrumentation — semantic detections vs enabled SIEM/platform rules."""

from __future__ import annotations

from core.evidence_graph import EvidenceGraph, evidence_graph_from_assessment_bundle
from core.models import AlertRule, AssessmentBundle, EvalResult
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "SI4_ALERT_INSTRUMENTATION"
EVAL_NAME = "SI-4 Alert Instrumentation Coverage"
CONTROL_REFS = [
    "SI-4",
    "SI-4(1)",
    "SI-4(4)",
    "SI-4(16)",
    "AU-5",
    "AU-6",
    "AC-2(4)",
    "AC-2(7)",
    "CM-8(3)",
    "CM-10",
    "CM-11",
    "SI-3",
]

# Required semantic types for instrumentation when they appear in SecurityEvent stream.
REQUIRED_SEMANTIC_TYPES: frozenset[str] = frozenset(
    {
        "identity.user_created",
        "identity.user_disabled",
        "identity.admin_role_granted",
        "identity.mfa_disabled",
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
        "network.firewall_rule_changed",
        "logging.audit_disabled",
        "compute.untracked_asset_created",
        "scanner.high_vulnerability_detected",
    }
)

# Must always have enabled, recipient-backed alert rules even if no recent event of that type.
MANDATORY_INSTRUMENTATION_TYPES: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "logging.audit_disabled",
    }
)


def _rules_for_semantic(rules: list[AlertRule], sem: str) -> list[AlertRule]:
    return [r for r in rules if sem in r.mapped_semantic_types]


def _enabled_with_recipients(rules: list[AlertRule]) -> list[AlertRule]:
    return [r for r in rules if r.enabled and bool(r.recipients)]


def eval_si4_alert_instrumentation_coverage(
    bundle: AssessmentBundle,
    graph: EvidenceGraph,
) -> EvalResult:
    """
    SI-4: enabled alert rules with recipients for required semantic event types.

    ``graph`` is accepted for API symmetry; evaluation uses the assessment bundle only.
    """
    _ = graph
    evidence: list[str] = []
    gaps: list[str] = []
    affected: list[str] = []
    fail = False
    partial = False

    rules = list(bundle.alert_rules)
    event_semantics = {e.semantic_type for e in bundle.events}

    in_scope = MANDATORY_INSTRUMENTATION_TYPES | (event_semantics & REQUIRED_SEMANTIC_TYPES)

    if not rules and in_scope:
        fail = True
        gaps.append("No alert rules are defined while security-relevant semantic events require instrumentation.")
        evidence.append("Alert rule catalog is empty.")

    # --- Per semantic: enabled rule + recipients; disabled-only coverage ---
    for sem in sorted(in_scope):
        covering = _rules_for_semantic(rules, sem)
        enabled_ok = _enabled_with_recipients(covering)
        if not covering:
            fail = True
            msg = f"No enabled alert rule covers {sem}."
            gaps.append(msg)
            evidence.append(msg)
            affected.append(sem)
            continue
        if not enabled_ok:
            fail = True
            msg = f"Alert rules reference {sem} but none are enabled with recipients."
            gaps.append(msg)
            evidence.append(msg)
            affected.append(sem)
            continue
        if any(not r.enabled for r in covering) and enabled_ok:
            partial = True
            gaps.append(f"Disabled alert configuration still present for {sem}; remove or enable to avoid ambiguity.")
            evidence.append(f"Some alert rules for {sem} are disabled while others are enabled.")

        r0 = enabled_ok[0]
        rec_s = ", ".join(r0.recipients)
        evidence.append(
            f"Alert rule {r0.name} covers {sem} and has recipients {rec_s}."
        )

    # --- sample_alert_ref / last_fired (enabled rules) ---
    event_semantics_interesting = event_semantics & REQUIRED_SEMANTIC_TYPES
    for rule in rules:
        if not rule.enabled or not rule.recipients:
            continue
        overlap = set(rule.mapped_semantic_types) & event_semantics_interesting
        if not overlap:
            continue
        if rule.sample_alert_ref:
            continue
        if rule.last_fired is None:
            fail = True
            msg = (
                f"Alert rule `{rule.rule_id}` covers observed semantics {sorted(overlap)} "
                "but has no sample_alert_ref and no recorded last_fired (no proof of firing)."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(rule.rule_id)
        else:
            partial = True
            msg = (
                f"Alert rule `{rule.rule_id}` has last_fired evidence but no sample_alert_ref — "
                "correlation proof is incomplete."
            )
            gaps.append(msg)
            evidence.append(msg)

    if fail:
        outcome = "FAIL"
        severity = "high"
        summary = "SI-4 alert instrumentation failed: missing, disabled, or unproven alerting for required semantics."
        recs = [
            "Generate SPL/KQL/GCP/AWS query.",
            "Add enabled alert.",
            "Add recipient list.",
            "Produce sample alert evidence.",
            "Link alert to incident/change response workflow.",
        ]
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "SI-4 alert instrumentation is partially complete (sample evidence or disabled duplicates)."
        recs = [
            "Produce sample alert evidence.",
            "Add enabled alert.",
            "Generate SPL/KQL/GCP/AWS query.",
            "Link alert to incident/change response workflow.",
        ]
    else:
        outcome = "PASS"
        severity = "low"
        summary = "SI-4: required semantic events have enabled alert rules with recipients."
        evidence.append("Enabled alert rules with recipients cover all in-scope semantic event types.")
        recs = []

    dedup: list[str] = []
    for x in recs:
        if x not in dedup:
            dedup.append(x)

    return EvalResult(
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        result=outcome,  # type: ignore[arg-type]
        controls=list(CONTROL_REFS),
        severity=severity,
        summary=summary,
        evidence=evidence or [summary],
        gaps=gaps,
        affected_assets=sorted(set(affected)),
        recommended_actions=dedup,
    )


def _canonical_to_pipeline(er: EvalResult) -> PipelineEvalResult:
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


def eval_alert_instrumentation(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
) -> PipelineEvalResult:
    """Pipeline entrypoint: canonical SI-4 alert instrumentation eval over the assessment bundle."""
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    canonical = eval_si4_alert_instrumentation_coverage(assessment, graph)
    return _canonical_to_pipeline(canonical)
