"""Compact evidence bundles for bounded future LLM workflows."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Sequence

from pydantic import Field

from core.deterministic_validators import ValidatorResult
from core.domain_models import ControlMapping, DomainModel, EvidenceArtifact, NormalizedFinding


def _dedupe(items: Sequence[str | None]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return sorted(out)


def _truncate(text: str | None, limit: int) -> str:
    value = " ".join(str(text or "").split())
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3].rstrip() + "..."


def _estimate_tokens(value: Any) -> int:
    payload = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return max(1, (len(payload) + 3) // 4)


class CompactVulnerabilityGroup(DomainModel):
    group_key: str = Field(..., alias="groupKey")
    vulnerability_id: str | None = Field(default=None, alias="vulnerabilityId")
    package_name: str | None = Field(default=None, alias="packageName")
    package_version: str | None = Field(default=None, alias="packageVersion")
    fixed_version: str | None = Field(default=None, alias="fixedVersion")
    severity: str = Field(..., alias="severity")
    resource: str | None = Field(default=None, alias="resource")
    image_digest: str | None = Field(default=None, alias="imageDigest")
    count: int = Field(..., alias="count", ge=0)
    statuses: list[str] = Field(default_factory=list, alias="statuses")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    control_ids: list[str] = Field(default_factory=list, alias="controlIds")
    representative_title: str = Field(..., alias="representativeTitle")
    representative_description: str = Field(..., alias="representativeDescription")
    critical_or_high: bool = Field(..., alias="criticalOrHigh")


class CompactEvidenceGroup(DomainModel):
    group_key: str = Field(..., alias="groupKey")
    control_id: str = Field(..., alias="controlId")
    evidence_type: str = Field(..., alias="evidenceType")
    source_system: str = Field(..., alias="sourceSystem")
    freshness_status: str = Field(..., alias="freshnessStatus")
    count: int = Field(..., alias="count", ge=0)
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    representative_summary: str = Field(..., alias="representativeSummary")
    trust_levels: list[str] = Field(default_factory=list, alias="trustLevels")


class CompactValidationSignal(DomainModel):
    validator_id: str = Field(..., alias="validatorId")
    status: str = Field(..., alias="status")
    control_id: str | None = Field(default=None, alias="controlId")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    message: str = Field(..., alias="message")
    remediation_hint: str = Field(..., alias="remediationHint")


class CompactEvidenceBundle(DomainModel):
    vulnerability_groups: list[CompactVulnerabilityGroup] = Field(default_factory=list, alias="vulnerabilityGroups")
    evidence_groups: list[CompactEvidenceGroup] = Field(default_factory=list, alias="evidenceGroups")
    critical_high_findings: list[CompactVulnerabilityGroup] = Field(default_factory=list, alias="criticalHighFindings")
    missing_evidence: list[CompactValidationSignal] = Field(default_factory=list, alias="missingEvidence")
    stale_evidence: list[CompactValidationSignal] = Field(default_factory=list, alias="staleEvidence")
    validation_signals: list[CompactValidationSignal] = Field(default_factory=list, alias="validationSignals")
    mapping_summary: dict[str, int] = Field(default_factory=dict, alias="mappingSummary")
    all_evidence_ids: list[str] = Field(default_factory=list, alias="allEvidenceIds")
    all_finding_ids: list[str] = Field(default_factory=list, alias="allFindingIds")
    source_counts: dict[str, int] = Field(default_factory=dict, alias="sourceCounts")
    raw_estimated_tokens: int = Field(..., alias="rawEstimatedTokens", ge=0)
    compact_estimated_tokens: int = Field(..., alias="compactEstimatedTokens", ge=0)


class EvidenceCompactor:
    """Build compact, ID-preserving evidence bundles."""

    def __init__(self, *, max_description_chars: int = 240) -> None:
        self.max_description_chars = max_description_chars

    def compact(
        self,
        *,
        evidence: Sequence[EvidenceArtifact],
        findings: Sequence[NormalizedFinding],
        control_mappings: Sequence[ControlMapping] = (),
        validation_results: Sequence[ValidatorResult] = (),
    ) -> CompactEvidenceBundle:
        raw_payload = {
            "evidence": [item.model_dump(mode="json", by_alias=True) for item in evidence],
            "findings": [item.model_dump(mode="json", by_alias=True) for item in findings],
            "controlMappings": [item.model_dump(mode="json", by_alias=True) for item in control_mappings],
            "validationResults": [item.model_dump(mode="json", by_alias=True) for item in validation_results],
        }
        vulnerability_groups = self._vulnerability_groups(findings)
        evidence_groups = self._evidence_groups(evidence)
        validation_signals = [self._validation_signal(row) for row in sorted(validation_results, key=lambda r: (r.control_id or "", r.validator_id, r.message))]
        missing = [
            signal
            for signal in validation_signals
            if signal.status in {"FAIL", "UNKNOWN"}
            and any(token in signal.message.lower() for token in ("missing", "no evidence", "no mapped evidence", "insufficient"))
        ]
        stale_validation = [
            signal
            for signal in validation_signals
            if "freshness" in signal.validator_id.lower()
            and (signal.status in {"FAIL", "WARN"} or "stale" in signal.message.lower() or "expired" in signal.message.lower())
        ]
        stale_from_evidence = [
            CompactValidationSignal(
                validatorId="evidence_freshness",
                status="FAIL" if item.freshness_status == "expired" else "WARN",
                controlId=",".join(item.control_ids) if item.control_ids else None,
                evidenceIds=[item.evidence_id],
                findingIds=[],
                message=f"Evidence {item.evidence_id} freshnessStatus={item.freshness_status}.",
                remediationHint="Refresh stale or expired evidence before LLM reasoning.",
            )
            for item in sorted(evidence, key=lambda e: e.evidence_id)
            if item.freshness_status in {"stale", "expired"}
        ]

        partial = CompactEvidenceBundle(
            vulnerabilityGroups=vulnerability_groups,
            evidenceGroups=evidence_groups,
            criticalHighFindings=[group for group in vulnerability_groups if group.critical_or_high],
            missingEvidence=missing,
            staleEvidence=sorted(stale_validation + stale_from_evidence, key=lambda s: (s.control_id or "", s.validator_id, ",".join(s.evidence_ids), s.message)),
            validationSignals=validation_signals,
            mappingSummary=self._mapping_summary(control_mappings),
            allEvidenceIds=_dedupe(
                [item.evidence_id for item in evidence]
                + [eid for finding in findings for eid in finding.evidence_ids]
                + [eid for mapping in control_mappings for eid in mapping.evidence_ids]
                + [eid for result in validation_results for eid in result.evidence_ids]
            ),
            allFindingIds=_dedupe(
                [item.finding_id for item in findings]
                + [fid for mapping in control_mappings for fid in mapping.finding_ids]
                + [fid for result in validation_results for fid in result.finding_ids]
            ),
            sourceCounts=dict(sorted(self._source_counts(evidence).items())),
            rawEstimatedTokens=_estimate_tokens(raw_payload),
            compactEstimatedTokens=1,
        )
        compact_payload = partial.model_dump(mode="json", by_alias=True)
        return partial.model_copy(update={"compact_estimated_tokens": _estimate_tokens(compact_payload)})

    def _vulnerability_groups(self, findings: Sequence[NormalizedFinding]) -> list[CompactVulnerabilityGroup]:
        grouped: dict[tuple[Any, ...], list[NormalizedFinding]] = defaultdict(list)
        for finding in findings:
            key = (
                finding.vulnerability_id,
                finding.package_name,
                finding.package_version,
                finding.fixed_version,
                finding.severity,
                finding.resource_id or finding.image_digest,
                finding.image_digest,
            )
            grouped[key].append(finding)

        out: list[CompactVulnerabilityGroup] = []
        for key in sorted(grouped, key=lambda k: tuple(str(x or "") for x in k)):
            rows = sorted(grouped[key], key=lambda f: f.finding_id)
            first = rows[0]
            group_key = "|".join(str(part or "") for part in key)
            out.append(
                CompactVulnerabilityGroup(
                    groupKey=group_key,
                    vulnerabilityId=first.vulnerability_id,
                    packageName=first.package_name,
                    packageVersion=first.package_version,
                    fixedVersion=first.fixed_version,
                    severity=first.severity,
                    resource=first.resource_id or first.image_digest,
                    imageDigest=first.image_digest,
                    count=len(rows),
                    statuses=_dedupe([row.status for row in rows]),
                    findingIds=_dedupe([row.finding_id for row in rows]),
                    evidenceIds=_dedupe([eid for row in rows for eid in row.evidence_ids]),
                    controlIds=_dedupe([cid for row in rows for cid in row.control_ids]),
                    representativeTitle=_truncate(first.title, self.max_description_chars),
                    representativeDescription=_truncate(first.description, self.max_description_chars),
                    criticalOrHigh=first.severity in {"CRITICAL", "HIGH"},
                )
            )
        return out

    def _evidence_groups(self, evidence: Sequence[EvidenceArtifact]) -> list[CompactEvidenceGroup]:
        grouped: dict[tuple[str, str, str, str], list[EvidenceArtifact]] = defaultdict(list)
        for item in evidence:
            control_ids = item.control_ids or ["UNMAPPED"]
            for control_id in control_ids:
                grouped[(control_id, item.source_type, item.source_system, item.freshness_status)].append(item)

        out: list[CompactEvidenceGroup] = []
        for key in sorted(grouped):
            rows = sorted(grouped[key], key=lambda e: e.evidence_id)
            control_id, evidence_type, source_system, freshness = key
            out.append(
                CompactEvidenceGroup(
                    groupKey="|".join(key),
                    controlId=control_id,
                    evidenceType=evidence_type,
                    sourceSystem=source_system,
                    freshnessStatus=freshness,
                    count=len(rows),
                    evidenceIds=_dedupe([row.evidence_id for row in rows]),
                    representativeSummary=_truncate(rows[0].normalized_summary, self.max_description_chars),
                    trustLevels=_dedupe([row.trust_level for row in rows]),
                )
            )
        return out

    def _validation_signal(self, result: ValidatorResult) -> CompactValidationSignal:
        return CompactValidationSignal(
            validatorId=result.validator_id,
            status=result.status,
            controlId=result.control_id,
            evidenceIds=_dedupe(result.evidence_ids),
            findingIds=_dedupe(result.finding_ids),
            message=_truncate(result.message, self.max_description_chars),
            remediationHint=_truncate(result.remediation_hint, self.max_description_chars),
        )

    @staticmethod
    def _mapping_summary(control_mappings: Sequence[ControlMapping]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for mapping in control_mappings:
            counts[mapping.mapping_confidence] = counts.get(mapping.mapping_confidence, 0) + 1
        return dict(sorted(counts.items()))

    @staticmethod
    def _source_counts(evidence: Sequence[EvidenceArtifact]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in evidence:
            counts[item.source_system] = counts.get(item.source_system, 0) + 1
        return counts


__all__ = [
    "CompactEvidenceBundle",
    "CompactEvidenceGroup",
    "CompactValidationSignal",
    "CompactVulnerabilityGroup",
    "EvidenceCompactor",
]
