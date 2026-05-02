"""AU-6 / AU-12 centralized log coverage — aggregation and correlation readiness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.evidence_graph import EvidenceGraph, evidence_graph_from_assessment_bundle
from core.models import Asset, AssessmentBundle, DeclaredInventoryRecord, EvalResult, LogSource
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.scanner_scope import _declared_decommissioned, _resolve_declared_asset
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "AU6_CENTRALIZED_LOG_COVERAGE"
EVAL_NAME = "AU-6/AU-12 Centralized Log Coverage"
CONTROL_REFS = [
    "AU-2",
    "AU-3",
    "AU-3(1)",
    "AU-6",
    "AU-6(1)",
    "AU-6(3)",
    "AU-7",
    "AU-8",
    "AU-12",
    "AU-9(2)",
    "SI-4",
]


def _tag_bool(tags: dict[str, str], *keys: str) -> bool:
    for k in keys:
        for tk, tv in tags.items():
            if str(tk).lower() == k.lower() and str(tv).strip().lower() in ("true", "1", "yes", "y"):
                return True
    return False


def _log_exempt(a: Asset) -> bool:
    return _tag_bool(a.tags, "log_exempt", "logging_exempt", "central_log_exempt")


def _now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.now(timezone.utc)


def _within_threshold(ts: datetime | None, now: datetime, hours: float) -> bool:
    if ts is None:
        return True
    return (now - ts) <= timedelta(hours=hours)


def _is_stale(ls: LogSource, now: datetime, hours: float) -> bool:
    if ls.status == "stale":
        return True
    if ls.last_seen is not None and not _within_threshold(ls.last_seen, now, hours):
        return True
    return False


def _sources_for_asset(bundle: AssessmentBundle, asset_id: str) -> list[LogSource]:
    return [ls for ls in bundle.log_sources if (ls.asset_id or "").strip() == asset_id]


def _has_active_central_recent(
    sources: list[LogSource],
    now: datetime,
    hours: float,
) -> bool:
    for ls in sources:
        if ls.status != "active":
            continue
        if ls.central_destination is None:
            continue
        if _within_threshold(ls.last_seen, now, hours):
            return True
    return False


def _critical_infra_asset(a: Asset) -> bool:
    return a.asset_type in ("compute", "database", "load_balancer") and a.criticality == "high"


def _log_required_declared_assets(bundle: AssessmentBundle) -> set[str]:
    """Asset ids (discovered) that back declared rows with log_required + in_boundary."""
    out: set[str] = set()
    for inv in bundle.declared_inventory:
        if not (inv.log_required and inv.in_boundary):
            continue
        if _declared_decommissioned(inv):
            continue
        a = _resolve_declared_asset(inv, bundle.assets)
        if a is not None:
            out.add(a.asset_id)
    return out


def eval_au6_au12_central_log_coverage(
    bundle: AssessmentBundle,
    graph: EvidenceGraph,
    *,
    now: datetime | None = None,
    hours_threshold: float = 24.0,
) -> EvalResult:
    """
    AU-6/AU-12: central aggregation / correlation for required assets and control-plane logs.

    ``graph`` is accepted for API symmetry with other evals; coverage is derived from the bundle.
    """
    _ = graph
    t = _now(now)
    evidence: list[str] = []
    gaps: list[str] = []
    affected: list[str] = []
    fail = False
    partial = False

    assets = list(bundle.assets)
    log_sources = list(bundle.log_sources)

    if not bundle.declared_inventory and not assets and not log_sources:
        return EvalResult(
            eval_id=EVAL_ID,
            name=EVAL_NAME,
            result="PASS",
            controls=list(CONTROL_REFS),
            severity="low",
            summary="No declared inventory, assets, or log sources to assess.",
            evidence=["No centralized logging evidence inputs present."],
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )

    required_asset_ids = _log_required_declared_assets(bundle)

    # --- 1. Declared log_required + in_boundary → active central log source ---
    for inv in bundle.declared_inventory:
        if not (inv.log_required and inv.in_boundary):
            continue
        if _declared_decommissioned(inv):
            continue
        a = _resolve_declared_asset(inv, assets)
        if a is None:
            partial = True
            msg = f"Declared `{inv.name}` requires logging but has no matching discovered asset to verify sources."
            gaps.append(msg)
            evidence.append(msg)
            continue
        srcs = _sources_for_asset(bundle, a.asset_id)
        if not _has_active_central_recent(srcs, t, hours_threshold):
            fail = True
            msg = f"{a.asset_id} requires logging but has no active central log source."
            gaps.append(msg)
            evidence.append(msg)
            affected.append(a.asset_id)

    # --- 2. Critical compute/database/load_balancer → active + recent ---
    for a in assets:
        if _log_exempt(a):
            continue
        if not _critical_infra_asset(a):
            continue
        srcs = _sources_for_asset(bundle, a.asset_id)
        if not _has_active_central_recent(srcs, t, hours_threshold):
            fail = True
            msg = (
                f"Critical {a.asset_type} asset `{a.asset_id}` lacks an active central log source "
                f"seen within the last {hours_threshold:g}h window."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(a.asset_id)
        else:
            for ls in srcs:
                if ls.status == "active" and ls.central_destination and ls.last_seen:
                    evidence.append(
                        f"{a.asset_id} central log source last_seen={ls.last_seen.isoformat().replace('+00:00', 'Z')}."
                    )
                    break

    # --- 3. Control-plane logs present and active ---
    cp = [ls for ls in log_sources if ls.source_type == "cloud_control_plane"]
    cp_ok = any(
        ls.status == "active" and ls.central_destination and _within_threshold(ls.last_seen, t, hours_threshold)
        for ls in cp
    )
    if not cp:
        fail = True
        gaps.append("No cloud control plane log source is defined for centralized audit of the control plane.")
        evidence.append("Control-plane logging must be present and active for AU-12 correlation.")
    elif not cp_ok:
        fail = True
        gaps.append("Cloud control plane log source is missing, inactive, or not recently seen centrally.")
        evidence.append("No active, recent cloud control plane log source with a central destination.")
    else:
        evidence.append("Cloud control plane log source is active.")

    # --- 4. Local sample without central sample ---
    for ls in log_sources:
        if ls.sample_local_event_ref and not ls.sample_central_event_ref:
            aid = (ls.asset_id or "").strip()
            crit = "moderate"
            if aid:
                for a in assets:
                    if a.asset_id == aid:
                        crit = a.criticality
                        break
            if crit == "high":
                fail = True
                msg = (
                    f"Log source `{ls.log_source_id}` has local sample evidence but no central sample; "
                    f"high-criticality context requires correlated proof."
                )
            else:
                partial = True
                msg = (
                    f"Log source `{ls.log_source_id}` has sample_local_event_ref but no sample_central_event_ref "
                    "(correlation evidence incomplete)."
                )
            gaps.append(msg)
            evidence.append(msg)
            if aid:
                affected.append(aid)

    # --- 5. Missing central_destination for required-asset log sources ---
    for ls in log_sources:
        aid = (ls.asset_id or "").strip()
        if not aid or aid not in required_asset_ids:
            continue
        if ls.central_destination is None:
            fail = True
            msg = f"Log source `{ls.log_source_id}` for required asset `{aid}` has no central_destination."
            gaps.append(msg)
            evidence.append(msg)
            affected.append(aid)

    # --- 6. Stale central logs ---
    for ls in log_sources:
        if ls.central_destination is None:
            continue
        if not _is_stale(ls, t, hours_threshold):
            continue
        aid = (ls.asset_id or "").strip()
        hi = aid and any(a.asset_id == aid and a.criticality == "high" for a in assets)
        req = aid in required_asset_ids
        if hi or req:
            fail = True
            msg = f"Central log source `{ls.log_source_id}` is stale beyond the {hours_threshold:g}h threshold for a required/high-sensitivity asset context."
        else:
            partial = True
            msg = f"Central log source `{ls.log_source_id}` is stale beyond the {hours_threshold:g}h threshold."
        gaps.append(msg)
        evidence.append(msg)
        if aid:
            affected.append(aid)

    if fail:
        outcome = "FAIL"
        severity = "high"
        summary = "AU-6/AU-12 centralized log coverage failed: missing or ineffective central ingestion for required signals."
        recs = [
            "Configure central log forwarding.",
            "Provide local and central copy of same event.",
            "Add source coverage dashboard/saved search.",
            "Generate missing SIEM query.",
        ]
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "AU-6/AU-12 partial: some correlation or freshness gaps without full failure."
        recs = [
            "Configure central log forwarding.",
            "Provide local and central copy of same event.",
            "Add source coverage dashboard/saved search.",
            "Generate missing SIEM query.",
        ]
    else:
        outcome = "PASS"
        severity = "low"
        summary = "AU-6/AU-12: required assets and control-plane paths show active central log coverage."
        evidence.append("Central log sources for in-scope assets appear active with central destinations.")
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


def eval_central_log_coverage(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
) -> PipelineEvalResult:
    """Pipeline entrypoint: canonical AU-6/AU-12 log coverage over the assessment bundle + graph."""
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    canonical = eval_au6_au12_central_log_coverage(assessment, graph)
    return _canonical_to_pipeline(canonical)
