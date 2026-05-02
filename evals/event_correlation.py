"""Cross-domain correlation of risky security events to inventory, scanning, logging, alerts, tickets, POA&M."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.control_mapper import get_controls_for_eval, get_controls_for_event
from core.evidence_graph import EvidenceGraph, evidence_graph_from_assessment_bundle
from core.models import AlertRule, AssessmentBundle, EvalResult, SecurityEvent
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "CROSS_DOMAIN_EVENT_CORRELATION"
EVAL_NAME = "Cross-Domain Security Event Correlation"

RISKY_SEMANTIC_TYPES: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
        "identity.admin_role_granted",
        "identity.mfa_disabled",
        "logging.audit_disabled",
        "compute.untracked_asset_created",
        "scanner.high_vulnerability_detected",
    }
)

# Missing ticket on these semantics is a FAIL-level gap (exposure / audit integrity).
_STRICT_TICKET_SEMANTICS: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
        "logging.audit_disabled",
    }
)


def _dedupe_controls(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _controls_for_bundle_events(semantics: set[str]) -> list[str]:
    base = list(get_controls_for_eval(EVAL_ID))
    for sem in sorted(semantics):
        base.extend(get_controls_for_event(sem))
    return _dedupe_controls(base)


def _asset_name(bundle: AssessmentBundle, asset_id: str | None) -> str:
    if not asset_id:
        return ""
    for a in bundle.assets:
        if a.asset_id == asset_id:
            return a.name
    return asset_id


def _inventory_covered(bundle: AssessmentBundle, asset_id: str | None) -> bool:
    if not asset_id:
        return False
    return any(d.asset_id == asset_id for d in bundle.declared_inventory)


def _scanner_covered(bundle: AssessmentBundle, asset_id: str | None) -> bool:
    if not asset_id:
        return False
    return any(t.asset_id == asset_id for t in bundle.scanner_targets)


def _central_logging_active(bundle: AssessmentBundle, asset_id: str | None) -> bool:
    if not asset_id:
        return False
    return any(ls.asset_id == asset_id and ls.status == "active" for ls in bundle.log_sources)


def _alert_rules_for_semantic(rules: list[AlertRule], sem: str) -> list[AlertRule]:
    return [r for r in rules if sem in r.mapped_semantic_types]


def _enabled_alert_rules(rules: list[AlertRule]) -> list[AlertRule]:
    return [r for r in rules if r.enabled and bool(r.recipients)]


def _alert_rule_enabled(bundle: AssessmentBundle, sem: str) -> bool:
    return bool(_enabled_alert_rules(_alert_rules_for_semantic(bundle.alert_rules, sem)))


def _alert_sample_available(bundle: AssessmentBundle, sem: str) -> bool:
    for r in _enabled_alert_rules(_alert_rules_for_semantic(bundle.alert_rules, sem)):
        if r.sample_alert_ref or r.last_fired is not None:
            return True
    return False


def _linked_ticket_id(bundle: AssessmentBundle, event: SecurityEvent) -> str | None:
    for t in bundle.tickets:
        if event.asset_id and event.asset_id in t.linked_asset_ids:
            return t.ticket_id
        if event.raw_ref and event.raw_ref in t.linked_event_ids:
            return t.ticket_id
        if event.event_id in t.linked_event_ids:
            return t.ticket_id
    return None


def _poam_item_id(bundle: AssessmentBundle, asset_id: str | None) -> str | None:
    if not asset_id:
        return None
    aid = asset_id.strip().lower()
    for p in bundle.poam_items:
        if p.asset_identifier.strip().lower() == aid:
            return p.poam_id
    return None


def _exposure_duration(event: SecurityEvent) -> str | None:
    meta = event.metadata or {}
    for key in ("exposure_duration", "duration", "exposure_window", "dwell_time"):
        v = meta.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


def _build_correlation_row(bundle: AssessmentBundle, event: SecurityEvent) -> dict[str, Any]:
    aid = event.asset_id
    inv = _inventory_covered(bundle, aid)
    scan = _scanner_covered(bundle, aid)
    log_ok = _central_logging_active(bundle, aid)
    alert_on = _alert_rule_enabled(bundle, event.semantic_type)
    sample_ok = _alert_sample_available(bundle, event.semantic_type) if alert_on else False
    ticket_id = _linked_ticket_id(bundle, event)
    poam_id = _poam_item_id(bundle, aid)
    exposure = _exposure_duration(event)

    missing: list[str] = []
    if not inv:
        missing.append("inventory")
    if not scan:
        missing.append("scanner_scope")
    if not log_ok:
        missing.append("central_logging")
    if not alert_on:
        missing.append("alert_rule")
    if alert_on and not sample_ok:
        missing.append("alert_sample")
    if not ticket_id:
        missing.append("linked_ticket")

    return {
        "event_id": event.event_id,
        "semantic_type": event.semantic_type,
        "timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
        "actor": event.actor,
        "asset_id": aid,
        "asset_name": _asset_name(bundle, aid),
        "inventory_covered": inv,
        "scanner_covered": scan,
        "central_logging_active": log_ok,
        "alert_rule_enabled": alert_on,
        "alert_sample_available": sample_ok,
        "linked_ticket_id": ticket_id,
        "poam_item_id": poam_id,
        "exposure_duration": exposure if exposure is not None else "unknown",
        "missing_evidence": missing,
    }


def _evidence_line(row: dict[str, Any]) -> str:
    aid = row.get("asset_id") or "unknown-asset"
    name = row.get("asset_name") or ""
    asset_part = f"{aid}" + (f" ({name})" if name and name != aid else "")
    eid = row.get("event_id")
    st = row.get("semantic_type")
    ticket = row.get("linked_ticket_id")
    ticket_s = "true" if ticket else "false"
    return (
        f"Event {eid} {st} affected {asset_part}; "
        f"scanner_covered={row.get('scanner_covered')}; "
        f"alert_rule_enabled={row.get('alert_rule_enabled')}; "
        f"linked_ticket={ticket_s}."
    )


def _write_correlations_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def eval_cross_domain_event_correlation(
    bundle: AssessmentBundle,
    graph: EvidenceGraph,
    *,
    output_dir: Path | None = None,
) -> EvalResult:
    """
    Correlate risky semantic events across inventory, scanner, logging, alerts, tickets, POA&M.

    ``graph`` is accepted for API symmetry; evaluation uses the assessment bundle only.
    Writes ``correlations.json`` under ``output_dir`` when provided.
    """
    _ = graph
    risky_events = [e for e in bundle.events if e.semantic_type in RISKY_SEMANTIC_TYPES]
    semantics_seen = {e.semantic_type for e in risky_events}
    controls = _controls_for_bundle_events(semantics_seen)

    correlations: list[dict[str, Any]] = []
    for ev in sorted(risky_events, key=lambda e: (e.timestamp, e.event_id)):
        correlations.append(_build_correlation_row(bundle, ev))

    evidence = [_evidence_line(r) for r in correlations] if correlations else [
        "No in-scope risky semantic events were present in the security event stream."
    ]

    fail = False
    partial = False
    gaps: list[str] = []
    affected: list[str] = []

    for row in correlations:
        sem = str(row["semantic_type"])
        missing = set(row["missing_evidence"])
        strict_ticket = sem in _STRICT_TICKET_SEMANTICS

        if "alert_rule" in missing or "central_logging" in missing:
            fail = True
            gaps.append(
                f"{row['event_id']}: missing required observability ({', '.join(sorted(missing & {'alert_rule', 'central_logging'}))})."
            )
            affected.append(str(row.get("asset_id") or row["event_id"]))
        elif strict_ticket and "linked_ticket" in missing:
            fail = True
            gaps.append(f"{row['event_id']}: risky exposure/audit event requires linked incident/change ticket.")
            affected.append(str(row.get("asset_id") or row["event_id"]))
        elif "linked_ticket" in missing:
            partial = True
            gaps.append(f"{row['event_id']}: alert and logging correlate but no linked ticket.")
            affected.append(str(row.get("asset_id") or row["event_id"]))
        elif "alert_sample" in missing or "scanner_scope" in missing or "inventory" in missing:
            partial = True
            gaps.append(
                f"{row['event_id']}: core chain present; minor gap(s): "
                f"{', '.join(sorted(missing & {'alert_sample', 'scanner_scope', 'inventory'}))}."
            )

    if not risky_events:
        outcome: str = "PASS"
        severity = "low"
        summary = "Cross-domain correlation: no risky semantic events in scope."
        recs: list[str] = []
    elif fail:
        outcome = "FAIL"
        severity = "high"
        summary = "Cross-domain correlation failed: one or more risky events lack alert, central logging, or required ticket linkage."
        recs = [
            "Map detections to CMDB/inventory identifiers.",
            "Ensure scanner scope covers in-boundary assets.",
            "Enable central audit ingestion for the affected asset.",
            "Enable alert rules with recipients for the semantic type.",
            "Open and link an incident or change ticket to the event or asset.",
        ]
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "Cross-domain correlation is incomplete: minor evidence gaps (ticket, sample alert, inventory, or scanner scope)."
        recs = [
            "Link tickets to security events or assets for traceability.",
            "Capture sample alert / firing evidence for mapped rules.",
            "Reconcile inventory and scanner coverage for affected assets.",
        ]
    else:
        outcome = "PASS"
        severity = "low"
        summary = "Cross-domain correlation: risky events have correlated alert, logging, and ticket evidence."
        recs = []

    artifact_rel = "output/correlations.json"
    generated: list[str] = []
    if output_dir is not None:
        out_path = output_dir / "correlations.json"
        _write_correlations_file(
            out_path,
            {
                "eval_id": EVAL_ID,
                "eval_name": EVAL_NAME,
                "result": outcome,
                "correlations": correlations,
            },
        )
        generated.append(artifact_rel)

    dedup_recs: list[str] = []
    for x in recs:
        if x not in dedup_recs:
            dedup_recs.append(x)

    return EvalResult(
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        result=outcome,  # type: ignore[arg-type]
        controls=controls,
        severity=severity,
        summary=summary,
        evidence=evidence,
        gaps=gaps,
        affected_assets=sorted({a for a in affected if a}),
        recommended_actions=dedup_recs,
        generated_artifacts=generated,
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
            "generated_artifacts": er.generated_artifacts,
        },
    )


def eval_event_correlation(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
    *,
    output_dir: Path | None = None,
) -> PipelineEvalResult:
    """Pipeline entrypoint: cross-domain correlation over all risky events in the assessment bundle."""
    _ = event
    _ = asset
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    out_dir = output_dir if output_dir is not None else (bundle.source_root / "output")
    canonical = eval_cross_domain_event_correlation(assessment, graph, output_dir=out_dir)
    return _canonical_to_pipeline(canonical)


def eval_event_correlation_bundle(
    bundle: AssessmentBundle,
    graph: EvidenceGraph | None = None,
    *,
    output_dir: Path | None = None,
) -> EvalResult:
    """Run canonical correlation eval; optional ``output_dir`` for ``correlations.json``."""
    g = graph if graph is not None else evidence_graph_from_assessment_bundle(bundle)
    return eval_cross_domain_event_correlation(bundle, g, output_dir=output_dir)
