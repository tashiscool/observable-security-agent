"""Evidence maturity (0–5) and per-KSI automation scores for FedRAMP 20x packages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fedramp20x.evidence_registry import EvidenceRegistry, EvidenceSource
from fedramp20x.ksi_catalog import Ksi, KsiCatalog


def score_evidence_source(source: EvidenceSource) -> int:
    """
    Maturity for a single evidence source.

    0 = unsupported, 1 = narrative, 2 = manual artifact, 3 = structured export,
    4 = automated validation (scheduled/scriptable API collection),
    5 = continuous validation (API/hybrid with continuous or event-driven collection).
    """
    cm = source.collection_method
    fq = source.frequency
    fmt = source.evidence_format

    if cm in ("api", "hybrid"):
        if fq in ("continuous", "event_driven"):
            return 5
        if fq in ("daily", "weekly", "monthly", "quarterly", "annual"):
            return 4
        if fq == "manual":
            if fmt in ("json", "csv", "yaml"):
                return 3
            return 4

    if cm == "file":
        if fmt in ("json", "csv", "yaml"):
            return 3
        if fmt in ("pdf", "screenshot"):
            return 2
        if fmt == "markdown":
            return 1
        return 3

    # manual collection
    if fmt == "markdown":
        return 1
    if fmt in ("pdf", "screenshot"):
        return 2
    if fmt in ("json", "csv", "yaml"):
        return 3
    return 2


def evidence_sources_to_map(
    evidence_sources: Mapping[str, EvidenceSource] | Sequence[EvidenceSource],
) -> dict[str, EvidenceSource]:
    if isinstance(evidence_sources, Mapping):
        return dict(evidence_sources)
    return {s.id: s for s in evidence_sources}


def _ksi_as_dict(ksi: Ksi | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(ksi, Ksi):
        return ksi.model_dump(mode="json")
    return dict(ksi)


def _required_evidence_ids(ksi_dict: Mapping[str, Any]) -> set[str]:
    out: set[str] = set()
    for c in ksi_dict.get("pass_fail_criteria") or []:
        if not isinstance(c, dict):
            continue
        for eid in c.get("evidence_required") or []:
            out.add(str(eid))
    return out


def _criteria_map(criteria_results: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    if isinstance(criteria_results, Mapping):
        return {str(k): dict(v) if isinstance(v, Mapping) else {} for k, v in criteria_results.items()}
    out: dict[str, dict[str, Any]] = {}
    for row in criteria_results:
        if not isinstance(row, Mapping):
            continue
        cid = str(row.get("criteria_id") or "")
        if cid:
            out[cid] = dict(row)
    return out


def _criteria_evaluated(ksi_dict: Mapping[str, Any], criteria_results: Mapping[str, Any] | Sequence[Any] | None) -> bool:
    crits = [c for c in (ksi_dict.get("pass_fail_criteria") or []) if isinstance(c, dict) and c.get("criteria_id")]
    if not crits:
        return True
    if criteria_results is None:
        return False
    cmap = _criteria_map(criteria_results)
    for c in crits:
        cid = str(c.get("criteria_id"))
        row = cmap.get(cid)
        if row is None:
            return False
        if row.get("evaluated") is True:
            continue
        if row.get("evaluated") is False:
            return False
        st = str(row.get("status") or "").upper()
        if st in ("PASS", "FAIL", "PARTIAL", "OPEN", "NOT_APPLICABLE", "N/A"):
            continue
        return False
    return True


def _alerting_signal(source: EvidenceSource) -> bool:
    if "alert" in source.name.lower():
        return True
    coll = (source.collector or "").lower()
    if "alert" in coll or "siem" in coll or "soc" in coll:
        return True
    return source.category in ("incident_response", "logging")


def _continuous_collection(source: EvidenceSource) -> bool:
    return source.collection_method in ("api", "hybrid") and source.frequency in ("continuous", "event_driven")


def _has_continuous_alerting_evidence(reg: Mapping[str, EvidenceSource], ref_ids: set[str]) -> bool:
    has_c = any(_continuous_collection(reg[rid]) for rid in ref_ids if rid in reg)
    has_a = any(_alerting_signal(reg[rid]) for rid in ref_ids if rid in reg)
    return has_c and has_a


def compute_ksi_automation_score(
    ksi: Ksi | Mapping[str, Any],
    evidence_sources: Mapping[str, EvidenceSource] | Sequence[EvidenceSource],
    criteria_results: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> int:
    """
    Aggregate automation / evidence maturity score for one KSI (0–5).

    Caps: missing required evidence → max 2; ``validation_mode=manual`` → max 2;
    ``validation_mode=hybrid`` → max 4. Score 4 when criteria are evaluated and
    required evidence (or linked-only evidence) reaches automated tier (≥4). Score 5
    when continuous/event-driven API evidence and alerting-oriented evidence are both present.
    """
    k = _ksi_as_dict(ksi)
    reg = evidence_sources_to_map(evidence_sources)
    mode = str(k.get("validation_mode") or "manual")

    required = _required_evidence_ids(k)
    linked = {str(x) for x in (k.get("evidence_sources") or [])}
    all_refs = required | linked

    missing_required = any(rid not in reg for rid in required)

    scores: dict[str, int] = {}
    for rid in all_refs:
        if rid in reg:
            scores[rid] = score_evidence_source(reg[rid])

    if not all_refs:
        raw = 0
    elif required:
        if any(rid not in scores for rid in required):
            missing_required = True
            raw = 0
        else:
            raw = min(scores[rid] for rid in required)
    else:
        raw = max(scores.values()) if scores else 0

    crit_ok = _criteria_evaluated(k, criteria_results)

    if missing_required:
        linked_boost = max((scores[rid] for rid in linked if rid in scores), default=0)
        merged = max(raw, linked_boost)
        return min(merged, 2)
    if mode == "manual":
        return min(raw, 2)

    if not crit_ok:
        return min(raw, 3)

    if mode == "hybrid":
        if raw >= 4:
            return 4
        return min(raw, 4)

    if raw >= 4 and _has_continuous_alerting_evidence(reg, all_refs):
        return 5
    if raw >= 4:
        return 4
    return min(raw, 5)


def infer_criteria_results_from_ksi_result(
    ksi: Ksi | Mapping[str, Any],
    ksi_result_row: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Build per-criterion rows for :func:`compute_ksi_automation_score` from a rollup KSI result."""
    kd = _ksi_as_dict(ksi)
    cids: list[str] = []
    for c in kd.get("pass_fail_criteria") or []:
        if isinstance(c, dict) and c.get("criteria_id"):
            cids.append(str(c["criteria_id"]))
    if not ksi_result_row:
        return {cid: {"criteria_id": cid, "evaluated": False} for cid in cids}
    st = str(ksi_result_row.get("status") or "").upper()
    evaluated = st in ("PASS", "FAIL", "PARTIAL", "OPEN", "NOT_APPLICABLE", "N/A")
    return {cid: {"criteria_id": cid, "evaluated": evaluated, "status": st} for cid in cids}


def ksi_remediation_hints(score: int, ksi_dict: Mapping[str, Any], *, missing_required: bool, mode: str) -> str:
    parts: list[str] = []
    if score >= 4:
        return "Already at or above automation score 4."
    if missing_required:
        parts.append("Register every ``evidence_required`` source id in the evidence registry and link artifacts.")
    if mode == "manual":
        parts.append("Raise ``validation_mode`` toward ``automated`` or ``hybrid`` once controls can be machine-checked.")
    elif mode == "hybrid":
        parts.append("Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence.")
    if not parts:
        parts.append("Add API or scheduled collectors (score 4) or continuous/event-driven collectors with alerting evidence (score 5).")
    else:
        parts.append("Increase evidence maturity (structured exports → automated → continuous validation).")
    return " ".join(parts)


def compute_ksi_evidence_posture(
    ksi: Ksi | Mapping[str, Any],
    evidence_sources: Mapping[str, EvidenceSource] | Sequence[EvidenceSource],
    criteria_results: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """
    Distinguish **missing evidence** (registry / criteria gap) from a **manual or file-primary**
    evidence path where sources are defined but low automation by design.

    ``missing_required_evidence`` means a criterion requires an evidence source id that is absent
    from the registry or could not be scored. That is an implementation gap, not an attestation choice.

    ``relies_on_manual_or_file_primary_evidence`` is True when required sources are all registered
    and the KSI leans on manual catalog mode and/or evidence sources scored ≤2 (narrative, PDF, etc.).
    """
    k = _ksi_as_dict(ksi)
    reg = evidence_sources_to_map(evidence_sources)
    mode = str(k.get("validation_mode") or "manual")
    required = _required_evidence_ids(k)
    linked = {str(x) for x in (k.get("evidence_sources") or [])}
    all_refs = required | linked
    missing_registry_ids = sorted({rid for rid in required if rid not in reg})
    scores: dict[str, int] = {}
    for rid in all_refs:
        if rid in reg:
            scores[rid] = score_evidence_source(reg[rid])
    missing_required = bool(missing_registry_ids) or (bool(required) and any(rid not in scores for rid in required))
    min_req: int | None = None
    if required and all(rid in scores for rid in required):
        min_req = min(scores[rid] for rid in required)
    relies_manual = (not missing_required) and (
        mode == "manual" or (min_req is not None and min_req <= 2)
    )
    maturity_score = compute_ksi_automation_score(ksi, reg, criteria_results)
    return {
        "missing_required_evidence": missing_required,
        "missing_evidence_registry_ids": missing_registry_ids,
        "relies_on_manual_or_file_primary_evidence": relies_manual,
        "validation_mode": mode,
        "automation_maturity_score": maturity_score,
    }


def compute_ksi_automation_details(
    ksi: Ksi | Mapping[str, Any],
    evidence_sources: Mapping[str, EvidenceSource] | Sequence[EvidenceSource],
    criteria_results: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> tuple[int, bool, str]:
    """Return (score, missing_required, validation_mode)."""
    posture = compute_ksi_evidence_posture(ksi, evidence_sources, criteria_results)
    return (
        posture["automation_maturity_score"],
        bool(posture["missing_required_evidence"]),
        str(posture["validation_mode"] or "manual"),
    )


def compute_package_evidence_maturity_summary(
    catalog_doc: KsiCatalog,
    evidence_registry: EvidenceRegistry,
    ksi_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Counts for package summary and per-KSI scores (for assessor reports)."""
    reg_map = {s.id: s for s in evidence_registry.sources}
    by_ksi = {str(r.get("ksi_id")): r for r in ksi_results if isinstance(r, dict) and r.get("ksi_id")}
    ksi_scores: dict[str, int] = {}
    mode_counts = {"manual": 0, "hybrid": 0, "automated": 0}
    missing_ids: list[str] = []
    manual_primary_ids: list[str] = []
    for k in catalog_doc.catalog:
        crit = infer_criteria_results_from_ksi_result(k, by_ksi.get(k.ksi_id))
        ksi_scores[k.ksi_id] = compute_ksi_automation_score(k, reg_map, crit)
        vm = str(k.validation_mode or "manual").strip().lower()
        if vm in mode_counts:
            mode_counts[vm] += 1
        else:
            mode_counts["manual"] += 1
        posture = compute_ksi_evidence_posture(k, reg_map, crit)
        if posture["missing_required_evidence"]:
            missing_ids.append(k.ksi_id)
        elif posture["relies_on_manual_or_file_primary_evidence"]:
            manual_primary_ids.append(k.ksi_id)
    total = len(catalog_doc.catalog)
    auto_n = sum(1 for s in ksi_scores.values() if s >= 4)
    pct = round(100.0 * auto_n / total, 2) if total else 0.0
    cat_auto = sum(1 for k in catalog_doc.catalog if k.automation_target)
    cat_pct = round(100.0 * cat_auto / total, 2) if total else 0.0
    return {
        "automated_ksis": auto_n,
        "automation_percentage": pct,
        "catalog_automation_target_ksis": cat_auto,
        "catalog_automation_percentage": cat_pct,
        "ksi_scores": ksi_scores,
        "ksi_validation_mode_counts": mode_counts,
        "ksi_manual_mode_count": mode_counts["manual"],
        "ksi_hybrid_mode_count": mode_counts["hybrid"],
        "ksi_automated_mode_count": mode_counts["automated"],
        "ksis_missing_required_evidence": len(missing_ids),
        "ksi_ids_missing_required_evidence": missing_ids,
        "ksis_manual_or_file_primary_evidence": len(manual_primary_ids),
        "ksi_ids_manual_or_file_primary_evidence": manual_primary_ids,
    }


def maturity_gaps_for_package(package: Mapping[str, Any]) -> list[tuple[str, int, str]]:
    """KSI id, automation score, remediation text for KSIs below score 4."""
    catalog = [k for k in (package.get("ksi_catalog") or []) if isinstance(k, dict)]
    reg_list = ((package.get("evidence_source_registry") or {}).get("sources")) or []
    reg_map: dict[str, EvidenceSource] = {}
    for row in reg_list:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        try:
            reg_map[str(row["id"])] = EvidenceSource.model_validate(row)
        except Exception:
            continue
    results_by_id = {
        str(r.get("ksi_id")): r for r in (package.get("ksi_validation_results") or []) if isinstance(r, dict) and r.get("ksi_id")
    }
    out: list[tuple[str, int, str]] = []
    for kd in catalog:
        kid = str(kd.get("ksi_id") or "")
        if not kid:
            continue
        crit = infer_criteria_results_from_ksi_result(kd, results_by_id.get(kid))
        posture = compute_ksi_evidence_posture(kd, reg_map, crit)
        score, missing_req, mode = compute_ksi_automation_details(kd, reg_map, crit)
        if score >= 4:
            continue
        hint = ksi_remediation_hints(score, kd, missing_required=missing_req, mode=mode)
        if posture["missing_required_evidence"]:
            hint = "[Missing required evidence — registry or criteria gap, not manual attestation] " + hint
        elif posture["relies_on_manual_or_file_primary_evidence"]:
            hint = (
                "[Manual or file-primary evidence path — sources registered; low automation by design, "
                "not the same as missing evidence] "
                + hint
            )
        out.append((kid, score, hint))
    return out
