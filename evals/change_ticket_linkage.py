"""CM-3 / SI-2 — change-management evidence linked to risky changes and High/Critical findings."""

from __future__ import annotations

from core.control_mapper import get_controls_for_eval
from core.evidence_graph import EvidenceGraph, evidence_graph_from_assessment_bundle
from core.models import AssessmentBundle, EvalResult, ScannerFinding, SecurityEvent, Ticket
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "CM3_CHANGE_EVIDENCE_LINKAGE"
EVAL_NAME = "CM-3/SI-2 Change Evidence Linkage"
CONTROL_REFS = list(get_controls_for_eval(EVAL_ID))

RISKY_CHANGE_SEMANTICS: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
        "network.firewall_rule_changed",
        "identity.admin_role_granted",
        "logging.audit_disabled",
        "compute.untracked_asset_created",
    }
)

_RECOMMENDED_ACTIONS_FULL: list[str] = [
    "Create/link change ticket.",
    "Add SIA.",
    "Add test evidence.",
    "Add approval.",
    "Add deployment evidence.",
    "Add verification scan evidence.",
]


def _asset_display_name(bundle: AssessmentBundle, asset_id: str | None) -> str:
    if not asset_id:
        return "unknown-asset"
    for a in bundle.assets:
        if a.asset_id == asset_id:
            return a.name
    return asset_id


def _ticket_links_event(t: Ticket, e: SecurityEvent) -> bool:
    if e.asset_id and e.asset_id in t.linked_asset_ids:
        return True
    if e.raw_ref and e.raw_ref in t.linked_event_ids:
        return True
    if e.event_id in t.linked_event_ids:
        return True
    return False


def _tickets_for_event(bundle: AssessmentBundle, e: SecurityEvent) -> list[Ticket]:
    return [t for t in bundle.tickets if _ticket_links_event(t, e)]


def _tickets_for_finding(bundle: AssessmentBundle, f: ScannerFinding) -> list[Ticket]:
    return [t for t in bundle.tickets if f.finding_id in t.linked_finding_ids]


def _open_high_critical(findings: list[ScannerFinding]) -> list[ScannerFinding]:
    out: list[ScannerFinding] = []
    for f in findings:
        if f.status != "open":
            continue
        if str(f.severity).lower() not in ("high", "critical"):
            continue
        out.append(f)
    return out


def _ticket_evidence_gaps(t: Ticket) -> list[str]:
    gaps: list[str] = []
    if not t.has_security_impact_analysis:
        gaps.append("SIA")
    if not t.has_testing_evidence:
        gaps.append("testing evidence")
    if not t.has_approval:
        gaps.append("approval")
    if not t.has_deployment_evidence:
        gaps.append("deployment evidence")
    if not t.has_verification_evidence:
        gaps.append("verification evidence")
    return gaps


def _humanize_gap_labels(labels: list[str]) -> str:
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def eval_cm3_si2_change_evidence_linkage(
    bundle: AssessmentBundle,
    graph: EvidenceGraph,
) -> EvalResult:
    """
    CM-3/SI-2: risky semantic events and open High/Critical findings must link to a change ticket
    with full SIA, test, approval, deployment, and verification evidence.

    ``graph`` is accepted for API symmetry; evaluation uses the assessment bundle only.
    """
    _ = graph
    evidence: list[str] = []
    gaps: list[str] = []
    affected: list[str] = []
    fail = False
    partial = False

    risky_events = [e for e in bundle.events if e.semantic_type in RISKY_CHANGE_SEMANTICS]
    hc_findings = _open_high_critical(bundle.scanner_findings)

    if not risky_events and not hc_findings:
        return EvalResult(
            eval_id=EVAL_ID,
            name=EVAL_NAME,
            result="PASS",
            controls=CONTROL_REFS,
            severity="low",
            summary="CM-3/SI-2: no risky change semantics or open High/Critical findings require change ticket linkage in this bundle.",
            evidence=["No in-scope risky change events or vulnerability remediations require change linkage."],
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )

    for e in sorted(risky_events, key=lambda x: (x.timestamp, x.event_id)):
        tickets = _tickets_for_event(bundle, e)
        if not tickets:
            fail = True
            msg = f"No ticket linked to event {e.event_id} {e.semantic_type}."
            gaps.append(msg)
            evidence.append(msg)
            if e.asset_id:
                affected.append(e.asset_id)
            continue
        t0 = tickets[0]
        miss = _ticket_evidence_gaps(t0)
        if miss:
            partial = True
            asset_nm = _asset_display_name(bundle, e.asset_id)
            gtxt = _humanize_gap_labels(miss)
            msg = (
                f"Ticket {t0.ticket_id} exists for change on {asset_nm} ({e.semantic_type}) "
                f"but lacks {gtxt}."
            )
            gaps.append(msg)
            evidence.append(msg)
            if e.asset_id:
                affected.append(e.asset_id)

    for f in sorted(hc_findings, key=lambda x: x.finding_id):
        tickets = _tickets_for_finding(bundle, f)
        aid = f.asset_id
        aname = _asset_display_name(bundle, aid)
        if not tickets:
            fail = True
            msg = f"No ticket linked to open {f.severity} finding {f.finding_id} ({f.title}) on {aname}."
            gaps.append(msg)
            evidence.append(msg)
            if aid:
                affected.append(aid)
            continue
        t0 = tickets[0]
        miss = _ticket_evidence_gaps(t0)
        if miss:
            partial = True
            gtxt = _humanize_gap_labels(miss)
            msg = (
                f"Ticket {t0.ticket_id} exists for {aname} vulnerability but lacks {gtxt}."
            )
            gaps.append(msg)
            evidence.append(msg)
            if aid:
                affected.append(aid)

    if fail:
        outcome = "FAIL"
        severity = "high"
        summary = "CM-3/SI-2 failed: high-risk change or High/Critical finding has no linked change ticket."
        recs = list(_RECOMMENDED_ACTIONS_FULL)
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "CM-3/SI-2: linked ticket(s) exist but change evidence is incomplete (SIA, test, approval, deploy, verify)."
        recs = list(_RECOMMENDED_ACTIONS_FULL)
    else:
        outcome = "PASS"
        severity = "low"
        summary = "CM-3/SI-2: all in-scope changes and vulnerability remediations have linked tickets with required evidence."
        ptickets = _collect_pass_tickets(bundle, risky_events, hc_findings)
        evidence = (
            [
                f"Linked ticket {t.ticket_id} satisfies change evidence requirements for in-scope items."
                for t in ptickets
            ]
            if ptickets
            else [summary]
        )
        recs = ["Retain ticket IDs, attachments, and approver identity in the change repository for audit samples."]

    dedup_ev = []
    for x in evidence:
        if x not in dedup_ev:
            dedup_ev.append(x)

    return EvalResult(
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        result=outcome,  # type: ignore[arg-type]
        controls=CONTROL_REFS,
        severity=severity,
        summary=summary,
        evidence=dedup_ev,
        gaps=gaps,
        affected_assets=sorted(set(affected)),
        recommended_actions=recs,
    )


def _collect_pass_tickets(
    bundle: AssessmentBundle,
    risky_events: list[SecurityEvent],
    hc_findings: list[ScannerFinding],
) -> list[Ticket]:
    seen: set[str] = set()
    out: list[Ticket] = []
    for e in risky_events:
        ts = _tickets_for_event(bundle, e)
        if not ts:
            continue
        t0 = ts[0]
        if not _ticket_evidence_gaps(t0) and t0.ticket_id not in seen:
            seen.add(t0.ticket_id)
            out.append(t0)
    for f in hc_findings:
        ts = _tickets_for_finding(bundle, f)
        if not ts:
            continue
        t0 = ts[0]
        if not _ticket_evidence_gaps(t0) and t0.ticket_id not in seen:
            seen.add(t0.ticket_id)
            out.append(t0)
    return out


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


def eval_change_ticket_linkage(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
) -> PipelineEvalResult:
    """Pipeline entrypoint: CM-3/SI-2 change linkage across all in-scope events and findings."""
    _ = event
    _ = asset
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    canonical = eval_cm3_si2_change_evidence_linkage(assessment, graph)
    return _canonical_to_pipeline(canonical)
