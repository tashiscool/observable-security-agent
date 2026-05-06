"""RA-5 scanner scope coverage — vulnerability scanner targets vs required assets."""

from __future__ import annotations

from typing import Any

from core.evidence_graph import (
    EvidenceGraph,
    REL_COVERED_BY_SCANNER_TARGET,
    evidence_graph_from_assessment_bundle,
    node_key,
)
from core.models import (
    Asset,
    AssessmentBundle,
    DeclaredInventoryRecord,
    EvalResult,
    ScannerFinding,
    ScannerTarget,
)
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "RA5_SCANNER_SCOPE_COVERAGE"
EVAL_NAME = "RA-5 Scanner Scope Coverage"
CONTROL_REFS = ["RA-5", "RA-5(3)", "RA-5(5)", "RA-5(6)", "CA-7", "SI-2"]


def _declared_decommissioned(inv: DeclaredInventoryRecord) -> bool:
    sc = (inv.system_component or "").lower()
    return "decommissioned" in sc or "decommissioned" in inv.name.lower()


def _tag_bool(tags: dict[str, str], *keys: str) -> bool:
    for k in keys:
        for tk, tv in tags.items():
            if str(tk).lower() == k.lower() and str(tv).strip().lower() in ("true", "1", "yes", "y"):
                return True
    return False


def _scanner_excluded(a: Asset) -> bool:
    return _tag_bool(a.tags, "scanner_exempt", "vuln_scan_exempt", "nessus_exempt")


def _is_prod_asset(a: Asset) -> bool:
    if a.environment == "prod":
        return True
    env = (a.tags.get("Environment") or a.tags.get("environment") or "").strip().lower()
    return env == "prod"


def _resolve_declared_asset(inv: DeclaredInventoryRecord, assets: list[Asset]) -> Asset | None:
    if inv.asset_id and str(inv.asset_id).strip():
        aid = str(inv.asset_id).strip()
        for a in assets:
            if a.asset_id == aid:
                return a
    nm = inv.name.strip()
    if nm:
        for a in assets:
            if a.name == nm or a.asset_id == nm:
                return a
    pip = (inv.expected_private_ip or "").strip()
    if pip:
        for a in assets:
            if pip in a.private_ips:
                return a
    pub = (inv.expected_public_ip or "").strip()
    if pub:
        for a in assets:
            if pub in a.public_ips:
                return a
    return None


def _target_matches_declared(st: ScannerTarget, inv: DeclaredInventoryRecord) -> bool:
    if inv.asset_id and str(inv.asset_id).strip():
        aid = str(inv.asset_id).strip()
        if st.asset_id == aid or st.target_id == aid:
            return True
    nm = inv.name.strip()
    if nm and (st.asset_id == nm or st.target_id == nm or (st.hostname and st.hostname.strip() == nm)):
        return True
    pip = (inv.expected_private_ip or "").strip()
    if pip and st.ip and st.ip.strip() == pip:
        return True
    pub = (inv.expected_public_ip or "").strip()
    if pub and st.ip and st.ip.strip() == pub:
        return True
    return False


def _incoming_scanner_edges(graph: EvidenceGraph, asset_id: str) -> list[dict[str, Any]]:
    return graph.find_edges(from_id=node_key("asset", asset_id), relationship=REL_COVERED_BY_SCANNER_TARGET)


def _scanner_target_from_to_key(bundle: AssessmentBundle, to_key: str) -> ScannerTarget | None:
    if not to_key.startswith("scanner_target::"):
        return None
    rest = to_key[len("scanner_target::") :]
    if "::" not in rest:
        return None
    sname, _, tid = rest.partition("::")
    for st in bundle.scanner_targets:
        if st.scanner_name == sname and st.target_id == tid:
            return st
    return None


def _declared_scanner_covered(inv: DeclaredInventoryRecord, bundle: AssessmentBundle, graph: EvidenceGraph) -> bool:
    asset = _resolve_declared_asset(inv, bundle.assets)
    if asset is not None and _incoming_scanner_edges(graph, asset.asset_id):
        return True
    return any(_target_matches_declared(st, inv) for st in bundle.scanner_targets)


def _credentialed_gap_for_asset(bundle: AssessmentBundle, graph: EvidenceGraph, asset_id: str) -> bool:
    """True if asset has scanner coverage but no credentialed target among covering edges."""
    edges = _incoming_scanner_edges(graph, asset_id)
    if not edges:
        return False
    cred = False
    for e in edges:
        st = _scanner_target_from_to_key(bundle, e["to"])
        if st and st.credentialed:
            cred = True
            break
    return not cred


def eval_ra5_scanner_scope_coverage(bundle: AssessmentBundle, graph: EvidenceGraph) -> EvalResult:
    evidence: list[str] = []
    gaps: list[str] = []
    affected: list[str] = []
    fail = False
    partial = False

    assets = list(bundle.assets)
    targets = list(bundle.scanner_targets)
    findings = list(bundle.scanner_findings)

    if not bundle.declared_inventory and not assets and not targets:
        return EvalResult(
            eval_id=EVAL_ID,
            name=EVAL_NAME,
            result="PASS",
            controls=list(CONTROL_REFS),
            severity="low",
            summary="No declared inventory, discovered assets, or scanner targets to assess.",
            evidence=["No scanner scope inputs present."],
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )

    scan_relevant_assets = [
        a for a in assets if a.asset_type in ("compute", "database") and not _scanner_excluded(a)
    ]
    if scan_relevant_assets and not targets and not findings:
        partial = True
        msg = (
            "No scanner target export or scanner finding export was provided for discovered compute/database assets; "
            "RA-5 scanner scope cannot be proven from live evidence."
        )
        gaps.append(msg)
        evidence.append(msg)
        affected.extend(a.asset_id for a in scan_relevant_assets)

    # --- 1. Declared scanner_required + in_boundary ---
    for inv in bundle.declared_inventory:
        if not (inv.scanner_required and inv.in_boundary):
            continue
        if _declared_decommissioned(inv):
            continue
        if not _declared_scanner_covered(inv, bundle, graph):
            fail = True
            aid = inv.asset_id or inv.name
            msg = (
                f"{aid} is in declared inventory and scanner_required=true, "
                "but no scanner target covers asset_id/name/IP."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(str(aid))

    # --- 2. Discovered prod compute/database ---
    for a in assets:
        if a.asset_type not in ("compute", "database"):
            continue
        if not _is_prod_asset(a):
            continue
        if _scanner_excluded(a):
            continue
        if not _incoming_scanner_edges(graph, a.asset_id):
            fail = True
            msg = (
                f"Discovered production {a.asset_type} asset `{a.asset_id}` has no scanner target coverage "
                "(not explicitly exempt)."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(a.asset_id)

    # --- 3. Credentialed scan (compute/database with coverage) ---
    seen_assets: set[str] = set()
    for a in assets:
        if a.asset_type not in ("compute", "database"):
            continue
        if a.asset_id in seen_assets:
            continue
        seen_assets.add(a.asset_id)
        if not _incoming_scanner_edges(graph, a.asset_id):
            continue
        if _credentialed_gap_for_asset(bundle, graph, a.asset_id):
            partial = True
            msg = (
                f"Asset `{a.asset_id}` has scanner targets but none are marked credentialed — "
                "confirm privileged/credentialed scan configuration."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(a.asset_id)

    # --- 4. High/Critical finding without scanner target ---
    for sf in findings:
        if str(sf.severity).lower() not in ("high", "critical"):
            continue
        aid = (sf.asset_id or "").strip()
        if not aid:
            continue
        if not _incoming_scanner_edges(graph, aid):
            fail = True
            msg = (
                f"Scanner finding `{sf.finding_id}` ({sf.severity}) on asset `{aid}` contradicts "
                "missing scanner target coverage for that asset."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(aid)

    # --- 5. Stale scanner targets (no matching asset edge) ---
    for st in targets:
        sk = node_key("scanner_target", f"{st.scanner_name}::{st.target_id}")
        outs = graph.find_edges(to_id=sk, relationship=REL_COVERED_BY_SCANNER_TARGET)
        if not outs:
            partial = True
            msg = f"Scanner target {st.target_id} has no matching discovered or declared asset."
            gaps.append(msg)
            evidence.append(msg)

    if fail:
        outcome = "FAIL"
        severity = "high"
        summary = "RA-5 scanner scope failed: required assets lack coverage or findings contradict scope."
        recs = [
            "Add missing target to scanner scope.",
            "Confirm credentialed scan configuration.",
            "Export scanner target configuration as system-generated evidence.",
            "Create POA&M if coverage cannot be fixed immediately.",
        ]
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "RA-5 scanner scope has gaps: stale targets and/or credentialed scan posture."
        recs = [
            "Add missing target to scanner scope.",
            "Confirm credentialed scan configuration.",
            "Export scanner target configuration as system-generated evidence.",
            "Create POA&M if coverage cannot be fixed immediately.",
        ]
    else:
        outcome = "PASS"
        severity = "low"
        summary = "RA-5 scanner scope covers scanner-required and in-scope production compute/database assets."
        evidence.append("All scanner-required in-boundary declared records show scanner target coverage.")
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


def eval_scanner_scope(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
) -> PipelineEvalResult:
    """Pipeline entrypoint: canonical RA-5 scanner scope over the full assessment bundle + graph."""
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    canonical = eval_ra5_scanner_scope_coverage(assessment, graph)
    return _canonical_to_pipeline(canonical)
