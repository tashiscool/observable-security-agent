"""Human-readable reports for assurance packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.guardrails import enforce_guardrails, evaluate_report_guardrails


REPORT_FILES = {
    "executive": "executive-summary.md",
    "control": "control-assessment-report.md",
    "risks": "open-risks.md",
    "evidence": "evidence-table.md",
    "review": "reviewer-decisions.md",
}


def _cell(value: Any, *, empty: str = "None recorded") -> str:
    if isinstance(value, list):
        text = ", ".join(str(x) for x in value if str(x).strip())
    elif value is None:
        text = ""
    else:
        text = str(value)
    text = text.replace("\n", " ").replace("|", "/").strip()
    return text or empty


def _ids(values: Any) -> str:
    return _cell(values, empty="No evidence IDs")


def _by_id(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(row.get(key)): row for row in rows if row.get(key)}


def _findings_for_control(package: dict[str, Any], control_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for finding in package.get("findings") or []:
        if control_id in (finding.get("controlIds") or []):
            out.append(finding)
    mapping_finding_ids = {
        fid
        for mapping in package.get("controlMappings") or []
        if mapping.get("targetControlId") == control_id or mapping.get("sourceControlId") == control_id
        for fid in mapping.get("findingIds") or []
    }
    if mapping_finding_ids:
        by_finding = _by_id(package.get("findings") or [], "findingId")
        for fid in sorted(mapping_finding_ids):
            row = by_finding.get(fid)
            if row and row not in out:
                out.append(row)
    return out


def _validations_for_control(package: dict[str, Any], control_id: str) -> list[dict[str, Any]]:
    return [
        row
        for row in package.get("validationResults") or []
        if row.get("controlId") == control_id
    ]


def _recommendations_for_control(package: dict[str, Any], control_id: str) -> list[dict[str, Any]]:
    return [
        row
        for row in package.get("agentRecommendations") or []
        if row.get("controlId") == control_id
    ]


def _reviews_by_recommendation(package: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for row in package.get("humanReviewDecisions") or []:
        out.setdefault(str(row.get("recommendationId")), []).append(row)
    return out


def _assessment_by_control(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _by_id(package.get("assessmentResults") or [], "controlId")


def _open_high_findings(package: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        finding
        for finding in package.get("findings") or []
        if finding.get("status") == "OPEN" and finding.get("severity") in {"CRITICAL", "HIGH"}
    ]


def _recommendation_for_finding(package: dict[str, Any], finding_id: str) -> str:
    for rec in package.get("agentRecommendations") or []:
        if finding_id in (rec.get("findingIds") or []):
            return str(rec.get("summary") or rec.get("recommendationType") or "Recommendation recorded.")
    return "No recommendation recorded."


def _executive_summary(package: dict[str, Any]) -> str:
    manifest = package["manifest"]
    period = manifest.get("assessmentPeriod") or {}
    insufficient = manifest.get("controlsWithInsufficientEvidence") or []
    open_high = _open_high_findings(package)
    reviews = package.get("humanReviewDecisions") or []
    top_risks = open_high[:5]
    lines = [
        "# Executive summary",
        "",
        f"- **System:** {_cell(manifest.get('system'))}",
        f"- **Assessment period:** {_cell(period.get('start'))} to {_cell(period.get('end'))}",
        f"- **Framework / baseline:** {_cell(manifest.get('framework'))} / {_cell(manifest.get('baseline'))}",
        f"- **Package status:** {_cell(manifest.get('packageStatus'))}",
        f"- **Controls assessed:** {len(manifest.get('controlsAssessed') or [])}",
        f"- **Controls with insufficient evidence:** {len(insufficient)} ({_cell(insufficient, empty='none')})",
        f"- **Open critical/high findings:** {len(open_high)}",
        f"- **Review status:** {len(reviews)} review decision(s) recorded; "
        + ("human review pending for remaining recommendations." if len(reviews) < len(package.get("agentRecommendations") or []) else "all recommendations have a recorded review decision."),
        "",
        "## Top risks",
        "",
    ]
    if not top_risks:
        lines.append("No open critical/high findings are recorded in the package.")
    else:
        for finding in top_risks:
            lines.append(
                f"- **{_cell(finding.get('severity'))}** `{_cell(finding.get('findingId'))}` "
                f"on `{_cell(finding.get('resourceId'))}`; controls `{_cell(finding.get('controlIds'))}`; "
                f"evidence IDs `{_ids(finding.get('evidenceIds'))}`."
            )
    lines.extend(["", "Evidence IDs appear in detailed sections below.", ""])
    return "\n".join(lines)


def _control_report(package: dict[str, Any]) -> str:
    assessments = _assessment_by_control(package)
    reviews_by_rec = _reviews_by_recommendation(package)
    lines = ["# Control assessment report", ""]
    for control in package.get("controls") or []:
        cid = str(control.get("controlId") or "")
        assessment = assessments.get(cid, {})
        evidence_ids = control.get("evidenceIds") or []
        findings = _findings_for_control(package, cid)
        validations = _validations_for_control(package, cid)
        recommendations = _recommendations_for_control(package, cid)
        reviewed = [
            review
            for rec in recommendations
            for review in reviews_by_rec.get(str(rec.get("recommendationId")), [])
        ]
        lines.extend(
            [
                f"## {cid} - {_cell(control.get('title'))}",
                "",
                f"- **Assessment status:** {_cell(assessment.get('status'), empty='Not assessed')}",
                f"- **Confidence:** {_cell(assessment.get('confidence'), empty='Not recorded')}",
                f"- **Evidence IDs:** `{_ids(evidence_ids)}`",
                f"- **Human review status:** {len(reviewed)} review decision(s) recorded; "
                + ("pending review." if recommendations and len(reviewed) < len(recommendations) else "no pending recommendation review recorded."),
                "",
                "### Evidence summary",
                "",
            ]
        )
        if evidence_ids:
            for eid in evidence_ids:
                evidence = _by_id(package.get("evidence") or [], "evidenceId").get(str(eid), {})
                lines.append(f"- `{eid}`: {_cell(evidence.get('normalizedSummary'))}")
        else:
            lines.append("- Evidence is missing for this control in the package.")
        lines.extend(["", "### Findings", ""])
        if findings:
            for finding in findings:
                lines.append(
                    f"- `{_cell(finding.get('findingId'))}` {_cell(finding.get('severity'))}/{_cell(finding.get('status'))}: "
                    f"{_cell(finding.get('title'))}; {_cell(finding.get('description'))}; "
                    f"evidence IDs `{_ids(finding.get('evidenceIds'))}`."
                )
        else:
            lines.append("- No findings are linked to this control.")
        lines.extend(["", "### Validation results", ""])
        if validations:
            for val in validations:
                lines.append(
                    f"- `{_cell(val.get('validatorId'))}`: {_cell(val.get('status'))}; "
                    f"{_cell(val.get('message'))}; evidence IDs `{_ids(val.get('evidenceIds'))}`."
                )
        else:
            lines.append("- No validation results are linked to this control.")
        lines.extend(["", "### Recommendations", ""])
        if recommendations:
            for rec in recommendations:
                lines.append(
                    f"- `{_cell(rec.get('recommendationId'))}` {_cell(rec.get('recommendationType'))}: "
                    f"{_cell(rec.get('summary'))}; evidence IDs `{_ids(rec.get('evidenceIds'))}`."
                )
        else:
            lines.append("- No recommendations are linked to this control.")
        lines.extend(["", "### Gaps", ""])
        gaps = assessment.get("gaps") or []
        if gaps:
            for gap in gaps:
                lines.append(f"- {_cell(gap)}")
        else:
            lines.append("- No gaps are recorded for this control.")
        lines.append("")
    return "\n".join(lines)


def _open_risks(package: dict[str, Any]) -> str:
    lines = [
        "# Open risks",
        "",
        "| Severity | Finding | Affected assets | Related controls | Evidence IDs | Recommendation | Owner | Due date |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    risks = _open_high_findings(package)
    if not risks:
        lines.append("| None recorded | - | - | - | No evidence IDs | No recommendation recorded. | Not recorded | Not recorded |")
        return "\n".join(lines) + "\n"
    for finding in risks:
        fid = str(finding.get("findingId") or "")
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(finding.get("severity")),
                    f"`{_cell(fid)}`",
                    _cell([finding.get("resourceId") or finding.get("imageDigest")]),
                    _cell(finding.get("controlIds")),
                    f"`{_ids(finding.get('evidenceIds'))}`",
                    _cell(_recommendation_for_finding(package, fid)),
                    _cell(finding.get("owner"), empty="Not recorded"),
                    _cell(finding.get("dueDate"), empty="Not recorded"),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _evidence_table(package: dict[str, Any]) -> str:
    lines = [
        "# Evidence table",
        "",
        "| Evidence ID | Source system | Source type | Account | Region | Resource | Observed at | Freshness | Controls |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for evidence in package.get("evidence") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{_cell(evidence.get('evidenceId'))}`",
                    _cell(evidence.get("sourceSystem")),
                    _cell(evidence.get("sourceType")),
                    _cell(evidence.get("accountId")),
                    _cell(evidence.get("region")),
                    _cell(evidence.get("resourceId") or evidence.get("resourceArn") or evidence.get("imageDigest")),
                    _cell(evidence.get("observedAt")),
                    _cell(evidence.get("freshnessStatus")),
                    _cell(evidence.get("controlIds")),
                ]
            )
            + " |"
        )
    if not package.get("evidence"):
        lines.append("| No evidence IDs | - | - | - | - | - | - | - | - |")
    return "\n".join(lines) + "\n"


def _reviewer_decisions(package: dict[str, Any]) -> str:
    lines = [
        "# Reviewer decisions",
        "",
        "| Recommendation ID | Reviewer | Decision | Justification | Timestamp | Evidence IDs |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    decisions = package.get("humanReviewDecisions") or []
    if not decisions:
        lines.append("| No recommendation reviewed | Human review pending | Pending | No reviewer decision has been recorded. | Not recorded | No evidence IDs |")
        return "\n".join(lines) + "\n"
    for decision in decisions:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{_cell(decision.get('recommendationId'))}`",
                    _cell(decision.get("reviewer")),
                    _cell(decision.get("decision")),
                    _cell(decision.get("justification")),
                    _cell(decision.get("timestamp")),
                    f"`{_ids(decision.get('evidenceIds'))}`",
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def build_human_readable_reports(package: dict[str, Any]) -> dict[str, str]:
    """Return all human-readable Markdown reports from an assurance package."""

    reports = {
        REPORT_FILES["executive"]: _executive_summary(package),
        REPORT_FILES["control"]: _control_report(package),
        REPORT_FILES["risks"]: _open_risks(package),
        REPORT_FILES["evidence"]: _evidence_table(package),
        REPORT_FILES["review"]: _reviewer_decisions(package),
    }
    for text in reports.values():
        enforce_guardrails(evaluate_report_guardrails(text, package=package))
    return reports


def write_human_readable_reports(output_dir: Path, package: dict[str, Any]) -> dict[str, Path]:
    """Write all human-readable assurance package reports."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for filename, text in build_human_readable_reports(package).items():
        path = output_dir / filename
        path.write_text(text, encoding="utf-8")
        written[filename] = path
    return written


def write_human_readable_reports_from_package(package_path: Path, output_dir: Path | None = None) -> dict[str, Path]:
    """Load ``assurance-package.json`` and write Markdown reports beside it or under output_dir."""

    package = json.loads(package_path.read_text(encoding="utf-8"))
    return write_human_readable_reports(output_dir or package_path.parent, package)
