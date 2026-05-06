"""FedRAMP ConMon / 3PAO reasonableness evaluation helpers.

This module does not decide that evidence is "good" because a tracker row says
so. It evaluates whether the row set and generated artifacts are *reasonable*:
authoritative source, full population, cadence freshness, traceability,
independent observability, and exception governance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from normalization.assessment_tracker_import import TrackerRow, parse_tracker_text


DEFAULT_CATALOG = Path(__file__).resolve().parents[1] / "config" / "conmon-catalog.yaml"


@dataclass(frozen=True)
class ObligationAssessment:
    obligation_id: str
    title: str
    cadence: str
    controls: list[str]
    ecosystems: list[str]
    matched_tracker_rows: list[int]
    coverage: str
    reasonableness_gaps: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "title": self.title,
            "cadence": self.cadence,
            "controls": self.controls,
            "ecosystems": self.ecosystems,
            "matched_tracker_rows": self.matched_tracker_rows,
            "coverage": self.coverage,
            "reasonableness_gaps": self.reasonableness_gaps,
        }


def load_conmon_catalog(path: Path | str = DEFAULT_CATALOG) -> dict[str, Any]:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"ConMon catalog is not a mapping: {p}")
    obligations = data.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        raise ValueError(f"ConMon catalog has no obligations: {p}")
    return data


def load_tracker_rows(path: Path | str | None) -> list[TrackerRow]:
    if path is None:
        return []
    p = Path(path)
    return parse_tracker_text(p.read_text(encoding="utf-8-sig"))


def _row_blob(row: TrackerRow) -> str:
    parts = [
        " ".join(row.controls or []),
        row.request_text,
        row.status or "",
        row.owner or "",
        row.assessor_comment or "",
        row.csp_comment or "",
        row.category,
    ]
    return " ".join(parts).lower()


def _keywords_for(obligation: Mapping[str, Any]) -> set[str]:
    stop = {
        "control",
        "controls",
        "evidence",
        "required",
        "ticket",
        "tickets",
        "review",
        "reviews",
        "system",
        "systems",
        "annual",
        "monthly",
        "continuous",
        "operate",
        "operates",
    }
    words: set[str] = set()
    for value in (
        obligation.get("title"),
        obligation.get("cadence"),
        " ".join(obligation.get("controls") or []),
        " ".join(obligation.get("evidence_required") or []),
    ):
        for token in str(value or "").lower().replace("/", " ").replace("-", " ").split():
            token = token.strip(".,:;()[]")
            if len(token) >= 4 and token not in stop:
                words.add(token)
    return words


def _row_matches_obligation(row: TrackerRow, obligation: Mapping[str, Any]) -> bool:
    row_controls = set(row.controls or [])
    obligation_controls = set(str(c) for c in (obligation.get("controls") or []))
    if row_controls & obligation_controls:
        return True
    blob = _row_blob(row)
    keywords = _keywords_for(obligation)
    hits = sum(1 for kw in keywords if kw in blob)
    return hits >= 4


def _is_closed_or_satisfied(row: TrackerRow) -> bool:
    status = (row.status or "").strip().lower()
    if status in {"closed", "complete", "completed", "satisfied", "accepted", "resolved"}:
        return True
    csp = (row.csp_comment or "").strip().lower()
    return any(h in csp for h in ("accepted", "satisfied", "attached final", "no further action"))


def _has_traceability(row: TrackerRow) -> bool:
    blob = _row_blob(row)
    return any(token in blob for token in ("ticket", "jira", "servicenow", "smartsheet", "attachment", "linked", "id", "export"))


def assess_conmon_reasonableness(
    *,
    catalog: Mapping[str, Any],
    tracker_rows: Iterable[TrackerRow] = (),
) -> dict[str, Any]:
    rows = list(tracker_rows)
    obligations = list(catalog.get("obligations") or [])
    assessments: list[ObligationAssessment] = []
    cadence_counts: dict[str, int] = {}
    ecosystem_counts: dict[str, int] = {}

    for ob in obligations:
        cadence = str(ob.get("cadence") or "unknown")
        cadence_counts[cadence] = cadence_counts.get(cadence, 0) + 1
        for eco in ob.get("ecosystems") or []:
            ecosystem_counts[str(eco)] = ecosystem_counts.get(str(eco), 0) + 1

        matched = [r for r in rows if _row_matches_obligation(r, ob)]
        gaps: list[str] = []
        if not matched:
            gaps.append("No tracker row maps to this obligation; add a Smartsheet/Jira/ServiceNow row or live evidence source.")
        elif not any(_has_traceability(r) for r in matched):
            gaps.append("Matched rows lack explicit ticket/export/attachment traceability.")
        if matched and not any(_is_closed_or_satisfied(r) for r in matched):
            gaps.append("Matched rows are not closed/satisfied; treat as open evidence requests until artifacts are attached.")

        required_ecosystems = set(str(x) for x in (ob.get("ecosystems") or []))
        if {"aws", "siem"} <= required_ecosystems:
            # This is the core "cloud + logs + response" reasonableness bar.
            evidence = " ".join(str(x).lower() for x in (ob.get("evidence_required") or []))
            if not all(x in evidence for x in ("cloudtrail", "siem")):
                gaps.append("Catalog obligation should name both control-plane/cloud logs and SIEM evidence.")
        if "ticketing" in required_ecosystems:
            systems = catalog.get("evidence_ecosystems", {}).get("ticketing", {}).get("systems", [])
            joined = " ".join(str(x).lower() for x in systems)
            if not all(name in joined for name in ("smartsheet", "jira", "servicenow")):
                gaps.append("Ticketing ecosystem must include Smartsheet, Jira, and ServiceNow adapters.")

        if not matched:
            coverage = "missing"
        elif gaps:
            coverage = "partial"
        else:
            coverage = "reasonable"

        assessments.append(
            ObligationAssessment(
                obligation_id=str(ob.get("id") or ""),
                title=str(ob.get("title") or ""),
                cadence=cadence,
                controls=[str(c) for c in (ob.get("controls") or [])],
                ecosystems=[str(e) for e in (ob.get("ecosystems") or [])],
                matched_tracker_rows=[r.row_index for r in matched],
                coverage=coverage,
                reasonableness_gaps=gaps,
            )
        )

    summary = {
        "obligations": len(assessments),
        "reasonable": sum(1 for a in assessments if a.coverage == "reasonable"),
        "partial": sum(1 for a in assessments if a.coverage == "partial"),
        "missing": sum(1 for a in assessments if a.coverage == "missing"),
        "tracker_rows": len(rows),
        "cadences": dict(sorted(cadence_counts.items())),
        "ecosystems": dict(sorted(ecosystem_counts.items())),
    }
    return {
        "schema_version": "1.0",
        "catalog_name": catalog.get("name"),
        "summary": summary,
        "reasonableness_tests": catalog.get("reasonableness_tests") or {},
        "evidence_ecosystems": catalog.get("evidence_ecosystems") or {},
        "obligation_assessments": [a.to_dict() for a in assessments],
    }


def render_reasonableness_markdown(result: Mapping[str, Any]) -> str:
    summary = result.get("summary") or {}
    lines = [
        "# ConMon / 3PAO Reasonableness Assessment",
        "",
        f"- Catalog: {result.get('catalog_name')}",
        f"- Obligations: {summary.get('obligations', 0)}",
        f"- Reasonable: {summary.get('reasonable', 0)}",
        f"- Partial: {summary.get('partial', 0)}",
        f"- Missing: {summary.get('missing', 0)}",
        f"- Tracker rows loaded: {summary.get('tracker_rows', 0)}",
        "",
        "## Evidence Ecosystems",
        "",
    ]
    ecosystems = result.get("evidence_ecosystems") or {}
    for key, meta in ecosystems.items():
        systems = ", ".join(str(x) for x in (meta.get("systems") or []))
        examples = ", ".join(str(x) for x in (meta.get("evidence_examples") or []))
        lines.append(f"- **{key}**: {systems}. Evidence: {examples}.")

    lines.extend(["", "## Reasonableness Tests", ""])
    for key, meta in (result.get("reasonableness_tests") or {}).items():
        lines.append(f"- **{key}**: {meta.get('question')}")

    lines.extend(["", "## Obligation Coverage", ""])
    lines.append("| Coverage | Cadence | Obligation | Matched rows | Gaps |")
    lines.append("|---|---|---|---:|---|")
    for row in result.get("obligation_assessments") or []:
        gaps = "; ".join(row.get("reasonableness_gaps") or [])
        lines.append(
            "| {coverage} | {cadence} | `{oid}` {title} | {matches} | {gaps} |".format(
                coverage=row.get("coverage"),
                cadence=row.get("cadence"),
                oid=row.get("obligation_id"),
                title=str(row.get("title") or "").replace("|", "\\|"),
                matches=len(row.get("matched_tracker_rows") or []),
                gaps=(gaps or "None").replace("|", "\\|"),
            )
        )

    lines.extend(
        [
            "",
            "## 3PAO Positioning",
            "",
            "This assessment treats Smartsheet/Jira/ServiceNow rows as workflow evidence, not as proof by themselves. "
            "A row is reasonable only when it links to authoritative system artifacts such as AWS CloudTrail/Config/IAM exports, "
            "CloudWatch or Splunk/Wazuh log evidence, scanner raw files, policy approvals, training rosters, or package artifacts.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reasonableness_outputs(result: Mapping[str, Any], output_dir: Path | str) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "conmon_reasonableness.json"
    md_path = out / "conmon_reasonableness.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_reasonableness_markdown(result), encoding="utf-8")
    return json_path, md_path
