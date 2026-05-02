"""CM-8 inventory reconciliation — declared vs discovered cloud assets."""

from __future__ import annotations

from collections import Counter
from core.evidence_graph import (
    EvidenceGraph,
    REL_INVENTORY_DESCRIBES_ASSET,
    evidence_graph_from_assessment_bundle,
    node_key,
)
from core.models import Asset, AssessmentBundle, DeclaredInventoryRecord, EvalResult
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "CM8_INVENTORY_RECONCILIATION"
EVAL_NAME = "CM-8 Inventory Reconciliation"
CONTROL_REFS = ["CM-8", "CM-8(1)", "CM-8(3)"]


def _tag_bool(tags: dict[str, str], *keys: str) -> bool:
    for k in keys:
        for tk, tv in tags.items():
            if str(tk).lower() == k.lower() and str(tv).strip().lower() in ("true", "1", "yes", "y"):
                return True
    return False


def _declared_decommissioned(inv: DeclaredInventoryRecord) -> bool:
    sc = (inv.system_component or "").lower()
    nm = inv.name.lower()
    return "decommissioned" in sc or "decommissioned" in nm


def _asset_decommissioned(a: Asset) -> bool:
    st = " ".join(f"{k}={v}" for k, v in a.tags.items()).lower()
    if "decommissioned" in st or _tag_bool(a.tags, "decommissioned", "status"):
        return True
    return str(a.tags.get("Status") or a.tags.get("status") or "").lower() == "decommissioned"


def _asset_inventory_exempt(a: Asset) -> bool:
    return _tag_bool(a.tags, "inventory_exempt", "iiw_exempt", "out_of_scope")


def _discovered_in_scope(a: Asset) -> bool:
    """In-scope for CM-8 reconciliation unless exempt or decommissioned."""
    if _asset_decommissioned(a) or _asset_inventory_exempt(a):
        return False
    return True


def _is_rogue_production(a: Asset) -> bool:
    if a.environment == "prod":
        return True
    env_tag = (a.tags.get("Environment") or a.tags.get("environment") or "").strip().lower()
    return env_tag == "prod"


def _asset_by_id(bundle: AssessmentBundle, asset_id: str) -> Asset | None:
    for a in bundle.assets:
        if a.asset_id == asset_id:
            return a
    return None


def _inv_by_id(bundle: AssessmentBundle, inventory_id: str) -> DeclaredInventoryRecord | None:
    for inv in bundle.declared_inventory:
        if inv.inventory_id == inventory_id:
            return inv
    return None


def _parse_node_key(full: str) -> tuple[str, str]:
    if "::" not in full:
        return "", full
    t, _, rest = full.partition("::")
    return t, rest


def _ip_mismatch(inv: DeclaredInventoryRecord, asset: Asset) -> tuple[bool, str | None]:
    """Return (mismatch, evidence_line)."""
    parts: list[str] = []
    exp_priv = (inv.expected_private_ip or "").strip()
    if exp_priv and exp_priv not in asset.private_ips:
        parts.append(f"expected private IP {exp_priv} but discovered {asset.private_ips or 'none'}")
    exp_pub = (inv.expected_public_ip or "").strip()
    if exp_pub and exp_pub not in asset.public_ips:
        parts.append(f"expected public IP {exp_pub} but discovered {asset.public_ips or 'none'}")
    if not parts:
        return False, None
    line = f"Declared inventory record {inv.name} " + "; ".join(parts) + "."
    return True, line


def eval_cm8_inventory_reconciliation(
    bundle: AssessmentBundle,
    graph: EvidenceGraph,
) -> EvalResult:
    """
    CM-8: reconcile declared inventory with discovered assets using the evidence graph.

    Uses ``INVENTORY_DESCRIBES_ASSET`` edges from :func:`evidence_graph_from_assessment_bundle`.
    """
    evidence: list[str] = []
    gaps: list[str] = []
    affected: list[str] = []
    fail = False
    partial = False

    declared = list(bundle.declared_inventory)
    assets = list(bundle.assets)

    if not declared and not assets:
        return EvalResult(
            eval_id=EVAL_ID,
            name=EVAL_NAME,
            result="PASS",
            controls=list(CONTROL_REFS),
            severity="low",
            summary="No declared inventory rows and no discovered assets to reconcile.",
            evidence=["No declared inventory records and no discovered cloud assets in scope."],
            gaps=[],
            affected_assets=[],
            recommended_actions=[],
        )

    # --- Duplicate checks (declared) ---
    id_counts = Counter(d.inventory_id for d in declared)
    dup_ids = [i for i, c in id_counts.items() if c > 1]
    if dup_ids:
        partial = True
        for i in dup_ids:
            gaps.append(f"Duplicate declared inventory_id `{i}` appears {id_counts[i]} times.")
        evidence.append(f"Declared inventory contains duplicate inventory_id entries: {dup_ids}.")

    name_counts = Counter(d.name.strip().lower() for d in declared if d.name.strip())
    dup_names = [n for n, c in name_counts.items() if c > 1]
    if dup_names:
        partial = True
        gaps.append(f"Duplicate declared inventory names detected: {dup_names}.")
        evidence.append("Declared inventory contains duplicate name values; resolve naming collisions.")

    asset_id_on_declared = [d.asset_id for d in declared if d.asset_id]
    aid_counts = Counter(str(x).strip() for x in asset_id_on_declared if str(x).strip())
    dup_asset_ids = [a for a, c in aid_counts.items() if c > 1]
    if dup_asset_ids:
        fail = True
        gaps.append(f"Duplicate declared asset_id values: {dup_asset_ids}.")
        evidence.append("Declared inventory lists the same asset_id on multiple rows — authoritative IIW conflict.")

    asset_ids_discovered = [a.asset_id for a in assets]
    if len(asset_ids_discovered) != len(set(asset_ids_discovered)):
        fail = True
        gaps.append("Duplicate discovered asset_id entries in the asset inventory export.")
        evidence.append("Discovered assets contain duplicate asset_id values.")

    # --- Declared in-boundary must link to discovered ---
    for inv in declared:
        if not inv.in_boundary or _declared_decommissioned(inv):
            continue
        inv_k = node_key("declared_inventory_record", inv.inventory_id)
        edges_out = graph.find_edges(from_id=inv_k, relationship=REL_INVENTORY_DESCRIBES_ASSET)
        if not edges_out:
            fail = True
            msg = (
                f"Declared inventory record {inv.name} ({inv.inventory_id}) is in boundary "
                "but has no matching discovered cloud asset."
            )
            gaps.append(msg)
            evidence.append(msg)
            affected.append(inv.inventory_id)

    # --- Discovered in-scope must be covered by declared ---
    for a in assets:
        if not _discovered_in_scope(a):
            continue
        ak = node_key("asset", a.asset_id)
        incoming = graph.find_edges(to_id=ak, relationship=REL_INVENTORY_DESCRIBES_ASSET)
        if not incoming:
            line = f"Discovered asset {a.asset_id} is not present in declared inventory."
            evidence.append(line)
            gaps.append(line)
            affected.append(a.asset_id)
            if _is_rogue_production(a):
                fail = True
                evidence.append(
                    f"Discovered production-class asset `{a.asset_id}` is absent from authoritative inventory (rogue asset risk)."
                )
            else:
                partial = True

    # --- IP mismatches on reconciled edges ---
    for e in graph.find_edges(relationship=REL_INVENTORY_DESCRIBES_ASSET):
        dt, did = _parse_node_key(e["from"])
        st, sid = _parse_node_key(e["to"])
        if dt != "declared_inventory_record" or st != "asset":
            continue
        inv = _inv_by_id(bundle, did)
        asset = _asset_by_id(bundle, sid)
        if inv is None or asset is None:
            continue
        bad, line = _ip_mismatch(inv, asset)
        if bad and line:
            partial = True
            gaps.append(line)
            evidence.append(line)
            affected.extend([inv.inventory_id, asset.asset_id])

    # --- Result ---
    if fail:
        outcome: str = "FAIL"
        severity = "high"
        summary = "CM-8 inventory reconciliation failed: authoritative gaps or rogue production assets detected."
        ordered_recs = [
            "Update inventory.",
            "Investigate rogue asset.",
            "Add scanner/logging coverage if asset is in boundary.",
            "Update Integrated Inventory Workbook (IIW) or authoritative CMDB to match discovered reality.",
            "Investigate rogue assets absent from inventory; validate ownership and boundary placement.",
        ]
    elif partial:
        outcome = "PARTIAL"
        severity = "moderate"
        summary = "CM-8 inventory reconciliation has minor mismatches (duplicates, IP drift, or non-prod orphans)."
        ordered_recs = [
            "Update inventory.",
            "Update inventory records and expected IP fields to match discovery exports.",
            "Add scanner/logging coverage if asset is in boundary.",
            "Add scanner and centralized logging coverage for in-boundary assets per CM-8(1)/CM-8(3).",
        ]
    else:
        outcome = "PASS"
        severity = "low"
        summary = "CM-8 declared inventory aligns with discovered cloud assets for in-scope resources."
        evidence.append("Declared in-boundary inventory records reconcile to discovered assets without blocking gaps.")
        ordered_recs = []

    seen_r: set[str] = set()
    dedup_recs: list[str] = []
    for r in ordered_recs:
        if r not in seen_r:
            seen_r.add(r)
            dedup_recs.append(r)

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
        recommended_actions=dedup_recs,
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


def eval_inventory_coverage(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
) -> PipelineEvalResult:
    """Pipeline entrypoint: build :class:`AssessmentBundle` + graph, run CM-8 eval, return pipeline result."""
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    graph = evidence_graph_from_assessment_bundle(assessment)
    canonical = eval_cm8_inventory_reconciliation(assessment, graph)
    return _canonical_to_pipeline(canonical)
