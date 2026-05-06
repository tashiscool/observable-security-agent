"""Deterministic mapping from normalized evidence/findings to controls."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Sequence

import yaml

from core.domain_models import ControlMapping, ControlRequirement, EvidenceArtifact, NormalizedFinding


MappingConfidence = Literal["EXACT_SOURCE_CONTROL", "STATIC_RULE", "HEURISTIC", "NEEDS_REVIEW"]

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "control-mapping-rules.yaml"


@dataclass(frozen=True)
class MappingSubject:
    """Evidence/finding pair or standalone evidence/finding row being mapped."""

    evidence: EvidenceArtifact | None = None
    finding: NormalizedFinding | None = None

    @property
    def evidence_ids(self) -> list[str]:
        ids = []
        if self.evidence:
            ids.append(self.evidence.evidence_id)
        if self.finding:
            ids.extend(self.finding.evidence_ids)
        return sorted(set(ids))

    @property
    def finding_ids(self) -> list[str]:
        return [self.finding.finding_id] if self.finding else []

    @property
    def source_controls(self) -> list[str]:
        controls: list[str] = []
        if self.evidence:
            controls.extend(self.evidence.control_ids)
        if self.finding:
            controls.extend(self.finding.control_ids)
        return _dedupe(controls)

    @property
    def source_ref(self) -> str:
        if self.evidence:
            return self.evidence.raw_ref
        if self.finding:
            return f"finding:{self.finding.finding_id}"
        return "unknown"


@dataclass(frozen=True)
class MappingRule:
    rule_id: str
    controls: tuple[str, ...]
    scanner: str | None = None
    source_type: str | None = None
    resource_type: str | None = None
    category_keywords: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    evidence_type: str | None = None
    rationale: str = ""


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _stable_id(*parts: Any) -> str:
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _default_rules() -> list[MappingRule]:
    return [
        MappingRule(
            rule_id="default_vulnerability_findings",
            source_type="vulnerability_scan_json",
            controls=("RA-5", "SI-2"),
            rationale="Vulnerability scanner findings support vulnerability monitoring and flaw remediation controls.",
        ),
        MappingRule(
            rule_id="default_scanner_names",
            scanner="nessus",
            controls=("RA-5", "SI-2"),
            rationale="Nessus output is treated as vulnerability scanning evidence.",
        ),
        MappingRule(
            rule_id="default_container_scans",
            source_type="container_scan_csv",
            controls=("RA-5", "SI-2", "CM-6"),
            rationale="Container scan output supports vulnerability and baseline configuration checks.",
        ),
        MappingRule(
            rule_id="default_audit_logging_config",
            source_type="cloud_config_json",
            evidence_type="audit_logging",
            category_keywords=("audit", "logging", "cloudtrail", "log group", "splunk", "cloudwatch"),
            controls=("AU",),
            rationale="Audit logging configuration evidence supports the AU family.",
        ),
        MappingRule(
            rule_id="default_identity_access",
            category_keywords=("identity", "iam", "access", "mfa", "password", "privilege", "user", "role"),
            controls=("AC", "IA"),
            rationale="Identity and access evidence supports access control and identification/authentication families.",
        ),
        MappingRule(
            rule_id="default_encryption",
            category_keywords=("encryption", "kms", "cipher", "tls", "fips", "cryptographic", "certificate"),
            controls=("SC-13", "SC"),
            rationale="Encryption configuration evidence supports cryptographic protection controls.",
        ),
        MappingRule(
            rule_id="default_configuration_baseline",
            category_keywords=("cis", "stig", "baseline", "configuration", "hardening", "benchmark"),
            controls=("CM-6",),
            rationale="Configuration baseline evidence supports CM-6.",
        ),
        MappingRule(
            rule_id="default_incident_security_event",
            source_type="security_event",
            category_keywords=("incident", "security event", "guardduty", "alert", "intrusion", "ioc"),
            controls=("IR", "AU"),
            rationale="Incident and security event evidence supports incident response and audit controls.",
        ),
        MappingRule(
            rule_id="default_high_vulnerabilities",
            severities=("CRITICAL", "HIGH"),
            controls=("RA-5", "SI-2", "CA-5"),
            rationale="Critical/high vulnerability findings support scanning, remediation, and POA&M tracking controls.",
        ),
    ]


def load_mapping_rules(path: Path | None = None) -> list[MappingRule]:
    """Load mapping rules from YAML, falling back to built-in defaults."""

    p = path or DEFAULT_RULES_PATH
    if not p.is_file():
        return _default_rules()
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    rows = raw.get("rules", raw if isinstance(raw, list) else [])
    if not isinstance(rows, list):
        raise ValueError(f"Control mapping rules must be a list or contain rules[]: {p}")

    rules: list[MappingRule] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"Control mapping rule {i} must be an object")
        controls = tuple(str(c).strip() for c in row.get("controls", []) if str(c).strip())
        if not controls:
            raise ValueError(f"Control mapping rule {i} missing controls")
        rules.append(
            MappingRule(
                rule_id=str(row.get("id") or row.get("rule_id") or f"rule-{i}"),
                scanner=str(row["scanner"]).strip() if row.get("scanner") else None,
                source_type=str(row["source_type"]).strip() if row.get("source_type") else None,
                resource_type=str(row["resource_type"]).strip() if row.get("resource_type") else None,
                evidence_type=str(row["evidence_type"]).strip() if row.get("evidence_type") else None,
                category_keywords=tuple(str(k).strip().lower() for k in row.get("category_keywords", []) if str(k).strip()),
                severities=tuple(str(s).strip().upper() for s in row.get("severities", []) if str(s).strip()),
                controls=controls,
                rationale=str(row.get("rationale") or "Configured static mapping rule."),
            )
        )
    return rules


def _control_index(controls: Sequence[ControlRequirement]) -> tuple[set[str], dict[str, list[str]]]:
    ids = {c.control_id for c in controls}
    by_family: dict[str, list[str]] = {}
    for control in controls:
        by_family.setdefault(control.family.upper(), []).append(control.control_id)
    return ids, by_family


def _expand_controls(
    targets: Sequence[str],
    *,
    control_ids: set[str],
    controls_by_family: dict[str, list[str]],
) -> list[str]:
    expanded: list[str] = []
    for target in targets:
        t = target.strip()
        if not t:
            continue
        if t in control_ids:
            expanded.append(t)
            continue
        family = t.upper()
        if family in controls_by_family:
            expanded.extend(controls_by_family[family])
            continue
        expanded.append(t)
    return _dedupe(expanded)


def _text(subject: MappingSubject) -> str:
    parts: list[str] = []
    if subject.evidence:
        e = subject.evidence
        parts.extend([e.source_system, e.source_type, e.resource_type or "", e.scanner or "", e.normalized_summary])
    if subject.finding:
        f = subject.finding
        parts.extend([f.source_system, f.scanner or "", f.title, f.description, f.package_name or "", f.vulnerability_id or ""])
    return " ".join(parts).lower()


def _rule_matches(rule: MappingRule, subject: MappingSubject) -> bool:
    ev = subject.evidence
    finding = subject.finding
    if rule.scanner:
        scanners = {_norm(ev.scanner) if ev else "", _norm(finding.scanner) if finding else ""}
        if _norm(rule.scanner) not in scanners:
            return False
    if rule.source_type and (not ev or _norm(ev.source_type) != _norm(rule.source_type)):
        return False
    if rule.resource_type and (not ev or _norm(ev.resource_type) != _norm(rule.resource_type)):
        return False
    if rule.severities and (not finding or finding.severity.upper() not in rule.severities):
        return False
    if rule.evidence_type and rule.evidence_type not in _text(subject):
        return False
    if rule.category_keywords and not any(keyword in _text(subject) for keyword in rule.category_keywords):
        return False
    return True


def _heuristic_controls(subject: MappingSubject) -> tuple[list[str], str]:
    text = _text(subject)
    if any(k in text for k in ("vulnerab", "cve", "patch", "package", "scanner")):
        return ["RA-5", "SI-2"], "Heuristic keyword match for vulnerability or patch management evidence."
    if any(k in text for k in ("audit", "log", "cloudtrail", "splunk", "cloudwatch")):
        return ["AU"], "Heuristic keyword match for audit logging evidence."
    if any(k in text for k in ("iam", "identity", "mfa", "password", "access", "privilege")):
        return ["AC", "IA"], "Heuristic keyword match for identity and access evidence."
    if any(k in text for k in ("encrypt", "kms", "tls", "fips", "cipher")):
        return ["SC-13", "SC"], "Heuristic keyword match for encryption evidence."
    if any(k in text for k in ("baseline", "configuration", "hardening", "stig", "cis")):
        return ["CM-6"], "Heuristic keyword match for configuration baseline evidence."
    if any(k in text for k in ("incident", "alert", "guardduty", "intrusion")):
        return ["IR", "AU"], "Heuristic keyword match for incident or alert evidence."
    return ["NEEDS_REVIEW"], "No deterministic control mapping rule matched this evidence/finding."


def _make_mapping(
    subject: MappingSubject,
    *,
    target_control: str,
    source_control: str,
    confidence: MappingConfidence,
    rationale: str,
    source_ref_suffix: str,
) -> ControlMapping:
    return ControlMapping(
        mappingId=f"map-{_stable_id(subject.source_ref, source_control, target_control, confidence, subject.finding_ids)}",
        sourceControlId=source_control,
        targetControlId=target_control,
        sourceFramework="normalized-evidence",
        targetFramework="NIST SP 800-53",
        relationship="supports" if confidence != "NEEDS_REVIEW" else "needs_review",
        rationale=rationale,
        evidenceIds=subject.evidence_ids,
        findingIds=subject.finding_ids,
        mappingConfidence=confidence,
        sourceRef=f"{subject.source_ref}#{source_ref_suffix}",
    )


def _subjects(evidence: Sequence[EvidenceArtifact], findings: Sequence[NormalizedFinding]) -> list[MappingSubject]:
    evidence_by_id = {item.evidence_id: item for item in evidence}
    out: list[MappingSubject] = []
    used_evidence: set[str] = set()
    for finding in findings:
        linked = [evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id]
        if linked:
            for item in linked:
                out.append(MappingSubject(evidence=item, finding=finding))
                used_evidence.add(item.evidence_id)
        else:
            out.append(MappingSubject(finding=finding))
    for item in evidence:
        if item.evidence_id not in used_evidence:
            out.append(MappingSubject(evidence=item))
    return out


def map_controls(
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
    controls: Sequence[ControlRequirement],
    *,
    rules_path: Path | None = None,
) -> list[ControlMapping]:
    """Map normalized evidence and findings to control requirements."""

    rules = load_mapping_rules(rules_path)
    control_ids, controls_by_family = _control_index(controls)
    mappings: list[ControlMapping] = []
    seen: set[tuple[str, str, str, tuple[str, ...], tuple[str, ...]]] = set()

    for subject in _subjects(evidence, findings):
        source_controls = subject.source_controls
        exact_targets = _expand_controls(source_controls, control_ids=control_ids, controls_by_family=controls_by_family)
        for target in exact_targets:
            mapping = _make_mapping(
                subject,
                target_control=target,
                source_control=target,
                confidence="EXACT_SOURCE_CONTROL",
                rationale="Source evidence or finding explicitly included this control ID.",
                source_ref_suffix="source-control",
            )
            key = (mapping.target_control_id, mapping.mapping_confidence, mapping.source_ref, tuple(mapping.evidence_ids), tuple(mapping.finding_ids))
            if key not in seen:
                seen.add(key)
                mappings.append(mapping)

        inferred: list[tuple[list[str], str, str]] = []
        for rule in rules:
            if _rule_matches(rule, subject):
                inferred.append((list(rule.controls), rule.rule_id, rule.rationale))
        if not inferred and not exact_targets:
            heuristic_controls, rationale = _heuristic_controls(subject)
            inferred.append((heuristic_controls, "heuristic", rationale))

        for targets, rule_id, rationale in inferred:
            expanded = _expand_controls(targets, control_ids=control_ids, controls_by_family=controls_by_family)
            for target in expanded:
                conflicts_with_source = bool(exact_targets) and target not in exact_targets
                confidence: MappingConfidence
                if target == "NEEDS_REVIEW":
                    confidence = "NEEDS_REVIEW"
                elif rule_id == "heuristic":
                    confidence = "NEEDS_REVIEW" if conflicts_with_source else "HEURISTIC"
                else:
                    confidence = "NEEDS_REVIEW" if conflicts_with_source else "STATIC_RULE"
                if conflicts_with_source:
                    rationale_text = (
                        f"{rationale} Inferred target conflicts with explicit source controls "
                        f"({', '.join(exact_targets)}), so human review is required."
                    )
                else:
                    rationale_text = rationale
                mapping = _make_mapping(
                    subject,
                    target_control=target,
                    source_control=",".join(exact_targets or source_controls or [rule_id]),
                    confidence=confidence,
                    rationale=rationale_text,
                    source_ref_suffix=rule_id,
                )
                key = (
                    mapping.target_control_id,
                    mapping.mapping_confidence,
                    mapping.source_ref,
                    tuple(mapping.evidence_ids),
                    tuple(mapping.finding_ids),
                )
                if key not in seen:
                    seen.add(key)
                    mappings.append(mapping)

    return mappings
