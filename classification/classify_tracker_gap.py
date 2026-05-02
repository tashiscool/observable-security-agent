"""Classify a FedRAMP assessment-tracker row into a structured evidence-gap type.

The assessor's evidence-request rows in a FedRAMP tracker are heterogeneous human-written
prose. This module turns each row into one of the canonical :class:`core.models.GapType`
values plus, where possible, a recommended artifact and a recommended validation step.

The classifier is **deterministic** and **substring-keyword-based**. It does not invent
evidence; it only labels what the assessor asked for. It is intentionally separate from
the surrounding category-classifier in :mod:`normalization.assessment_tracker_import`
(which buckets a row into ``inventory`` / ``scanner`` / ``logging`` / etc. for fixture
file routing). Here we go finer-grained: a row already classified as ``scanner`` could
become ``scanner_scope_missing``, ``vulnerability_scan_evidence_missing``, or
``credentialed_scan_evidence_missing`` depending on the precise wording.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.models import GapSeverity, GapType


__all__ = [
    "GapClassification",
    "classify_tracker_gap",
    "PHRASE_RULES",
]


@dataclass(frozen=True)
class GapClassification:
    """Result of classifying a tracker row."""

    gap_type: GapType
    severity: GapSeverity
    recommended_artifact: str | None
    recommended_validation: str | None
    matched_phrases: list[str]
    poam_required: bool


# ---------------------------------------------------------------------------
# Phrase rules — ORDER MATTERS. More specific rules must come before broader ones.
# Each entry: (gap_type, severity, recommended_artifact, recommended_validation, phrases)
# ---------------------------------------------------------------------------

_RECOMMENDED_ARTIFACTS: dict[GapType, str] = {
    "inventory_mismatch": "declared_inventory.csv reconciled against discovered_assets.json",
    "scanner_scope_missing": "scanner_targets.csv covering every in-boundary asset",
    "vulnerability_scan_evidence_missing": "scanner_findings.json export from latest credentialed scan",
    "credentialed_scan_evidence_missing": "scanner_targets.csv with credentialed=true + plugin/profile evidence",
    "centralized_log_missing": "central_log_sources.json showing source -> SIEM ingestion",
    "local_to_central_log_correlation_missing": (
        "central_log_sources.json plus a local audit log sample correlated with the central index"
    ),
    "alert_rule_missing": "alert_rules.json entry with controls + recipients",
    "alert_sample_missing": "sample_alert_ref pointing at an executed alert export",
    "response_action_missing": "tickets.json entry citing the alert with documented response",
    "change_ticket_missing": "tickets.json entry linking change request to deployed assets",
    "sia_missing": "tickets.json field security_impact_analysis=true with SIA attachment",
    "testing_evidence_missing": "tickets.json field test_evidence=true with test artifacts",
    "approval_missing": "tickets.json field approval_recorded=true with CAB minutes",
    "deployment_evidence_missing": "tickets.json field has_deployment_evidence=true with deploy log",
    "verification_evidence_missing": "tickets.json field has_verification_evidence=true with post-deploy proof",
    "exploitation_review_missing": (
        "scanner_findings.json finding with exploitation_review.queries[] + log_review_performed=true"
    ),
    "poam_update_missing": "poam.csv with current status, dates, and milestones",
    "deviation_request_missing": "poam.csv row with deviation_request_ref + approval evidence",
    "backup_evidence_missing": "backup_assets.json + most-recent backup execution log",
    "restore_test_missing": "restore_tests.json with measured RTO/RPO",
    "identity_listing_missing": "identity_users.json + privileged-account flag + MFA report",
    "password_policy_evidence_missing": "password policy export + IdP enforcement evidence",
    "crypto_fips_evidence_missing": "FIPS 140-2/3 module list + KMS rotation export + cipher policy",
    "traffic_flow_policy_missing": "data-flow diagram + security_group inventory + ports/protocols matrix",
    "unknown": None,  # type: ignore[dict-item]
}

_RECOMMENDED_VALIDATIONS: dict[GapType, str] = {
    "inventory_mismatch": "Run CM8_INVENTORY_RECONCILIATION on the produced CSV+JSON",
    "scanner_scope_missing": "Run RA5_SCANNER_SCOPE_COVERAGE",
    "vulnerability_scan_evidence_missing": "Re-import via `import-findings --format prowler|ocsf`",
    "credentialed_scan_evidence_missing": "Verify scanner_targets.credentialed flag in RA5_SCANNER_SCOPE_COVERAGE",
    "centralized_log_missing": "Run AU6_CENTRALIZED_LOG_COVERAGE",
    "local_to_central_log_correlation_missing": (
        "AU6_CENTRALIZED_LOG_COVERAGE local-vs-central correlation must show seen_last_24h=true"
    ),
    "alert_rule_missing": "Run SI4_ALERT_INSTRUMENTATION",
    "alert_sample_missing": "SI4_ALERT_INSTRUMENTATION requires sample_alert_ref to be non-empty",
    "response_action_missing": "Run CROSS_DOMAIN_EVENT_CORRELATION (alert -> ticket linkage)",
    "change_ticket_missing": "Run CM3_CHANGE_EVIDENCE_LINKAGE",
    "sia_missing": "CM3_CHANGE_EVIDENCE_LINKAGE expects security_impact_analysis=true",
    "testing_evidence_missing": "CM3_CHANGE_EVIDENCE_LINKAGE expects test_evidence=true",
    "approval_missing": "CM3_CHANGE_EVIDENCE_LINKAGE expects approval_recorded=true",
    "deployment_evidence_missing": "CM3_CHANGE_EVIDENCE_LINKAGE expects has_deployment_evidence=true",
    "verification_evidence_missing": "CM3_CHANGE_EVIDENCE_LINKAGE expects has_verification_evidence=true",
    "exploitation_review_missing": "Run RA5_EXPLOITATION_REVIEW",
    "poam_update_missing": "Run CA5_POAM_STATUS",
    "deviation_request_missing": "Validate poam.csv deviation columns then re-run CA5_POAM_STATUS",
    "backup_evidence_missing": "Validate backup_assets.json shape (no automated eval yet — manual review)",
    "restore_test_missing": "Validate restore_tests.json + measured RTO/RPO (manual review)",
    "identity_listing_missing": "Run AGENT_PERMISSION_SCOPE / IAM review (manual + automated)",
    "password_policy_evidence_missing": "Verify IdP password policy export (manual review)",
    "crypto_fips_evidence_missing": "Verify FIPS module list + KMS rotation (manual review)",
    "traffic_flow_policy_missing": "Validate SG inventory + DFD against authorization-scope.yaml",
    "unknown": None,  # type: ignore[dict-item]
}

# Each rule: (gap_type, severity, *phrases). Order = priority (first match wins).
_GAP_RULES: tuple[tuple[GapType, GapSeverity, tuple[str, ...]], ...] = (
    # ----- inventory --------------------------------------------------------
    (
        "inventory_mismatch",
        "high",
        (
            "inventory appears to be evolving",
            "discrepancies",
            "stale cmdb",
            "stale entries",
            "orphan",
            "orphaned entries",
            "reconcile declared",
            "reconcile inventory",
            "integrated inventory workbook",
            "iiw",
            "aws dump",
            "aws account dump",
            "trendmicro inventory",
            "system component inventory",
            "inventory of load balancers",
            "inventory of s3",
            "load balancer inventory",
            "ec2 inventory",
            "rds inventory",
            "vpc inventory",
            "s3 inventory",
            "alb/nlb inventory",
            "ip ranges",
            "ip allocation",
            "subnet listing",
            "asset inventory",
        ),
    ),
    # ----- scanner: most specific first -------------------------------------
    (
        "credentialed_scan_evidence_missing",
        "high",
        (
            "credentialed checks",
            "credentialed scan",
            "authenticated scan",
            "privileged access",
            "privileged scan",
            "credentialed-scan",
        ),
    ),
    (
        "vulnerability_scan_evidence_missing",
        "high",
        (
            "plugins",
            "signatures",
            "updated prior to each new scan",
            "vulnerability scan reports",
            "vulnerability scan report",
            "scan plugins",
            "scan signatures",
            "burp signatures",
            "nessus vulnerability scan",
        ),
    ),
    (
        "scanner_scope_missing",
        "high",
        (
            "provide evidence to display all system components that are scanned",
            "all system components that are scanned",
            "scan target list",
            "scan scope",
            "scanner scope",
            "in-boundary assets in scope",
            "in scope for scanning",
            "scanner_targets",
        ),
    ),
    # ----- exploitation review ---------------------------------------------
    (
        "exploitation_review_missing",
        "critical",
        (
            "historic audit logs",
            "historical audit log",
            "historical audit logs",
            "evidence of exploitation",
            "exploitation review",
            "exploit review",
            "ioc",
            "indicator of compromise",
            "high/critical vulnerabilities open",
            "critical vulnerabilities open",
            "compromise assessment",
        ),
    ),
    # ----- logging ----------------------------------------------------------
    (
        "local_to_central_log_correlation_missing",
        "high",
        (
            "local audit log",
            "local log",
            "same audit log contained within splunk",
            "matches centralized",
            "correlate local",
            "local-to-central",
            "forwarder healthcheck",
            "forwarder healthchecks",
            "forwarder healthy",
        ),
    ),
    (
        "centralized_log_missing",
        "high",
        (
            "centralized audit log aggregation",
            "central log aggregation",
            "centralized log",
            "central log",
            "centralized audit log",
            "log aggregation",
            "siem onboarding",
            "log forwarding",
            "log forwarder",
            "ingestion stale",
            "vpc flow log",
            "vpc flow logs",
            "cloudwatch logs",
        ),
    ),
    # ----- alerting / response ---------------------------------------------
    (
        "alert_sample_missing",
        "high",
        (
            "example alerts",
            "example alert that fired",
            "sample alert",
            "alert export",
            "saved search export",
        ),
    ),
    (
        "response_action_missing",
        "high",
        (
            "actions taken in response",
            "documented response action",
            "response action",
            "incident handling actions",
            "incident response evidence",
            "incident response",
            "incident ticket",
            "incident report",
            "us-cert",
            "cisa report",
            "cisa notification",
            "incident closure",
            "suspected incident",
            "confirmed incident",
        ),
    ),
    (
        "alert_rule_missing",
        "high",
        (
            "enabled alerts",
            "alert rules",
            "alert rule",
            "alerting",
            "recipient list",
            "alert recipient",
            "notification recipient",
            "guardduty notifications",
            "cloudwatch alarms",
            "cloudwatch alarm",
            "alert configuration",
            "alert dashboard",
            "saved search",
        ),
    ),
    # ----- change evidence chain (most specific first) ---------------------
    (
        "sia_missing",
        "high",
        (
            "sia",
            "security impact analysis",
            "sia performed before deployment",
            "no sia",
        ),
    ),
    (
        "testing_evidence_missing",
        "moderate",
        (
            "test documentation",
            "test evidence",
            "testing evidence",
            "testing artifacts",
            "test artifacts",
            "no test evidence",
        ),
    ),
    (
        "approval_missing",
        "moderate",
        (
            "approval evidence",
            "cab approval",
            "no approval",
            "missing approval",
            "change advisory board",
            "approval recorded",
        ),
    ),
    (
        "deployment_evidence_missing",
        "moderate",
        (
            "deployment evidence",
            "deploy evidence",
            "deployment log",
            "no deployment evidence",
            "missing deployment",
        ),
    ),
    (
        "verification_evidence_missing",
        "moderate",
        (
            "verification evidence",
            "post-deploy verification",
            "post-deploy",
            "no verification",
            "missing verification",
        ),
    ),
    (
        "change_ticket_missing",
        "high",
        (
            "change ticket",
            "change tickets",
            "change request",
            "rfc ticket",
            "jira",
            "no change ticket",
            "missing change ticket",
        ),
    ),
    # ----- POA&M / deviation ----------------------------------------------
    (
        "deviation_request_missing",
        "moderate",
        (
            "deviation request",
            "false positive request",
            "risk acceptance request",
            "vendor dependency",
            "operational requirement",
        ),
    ),
    (
        "poam_update_missing",
        "moderate",
        (
            "poa&m updated",
            "poa&m update",
            "poam updated",
            "poa&m",
            "poam",
            "plan of action",
        ),
    ),
    # ----- backup / recovery -----------------------------------------------
    (
        "restore_test_missing",
        "high",
        (
            "restore test",
            "recovery test",
            "rto",
            "rpo",
            "restore-test ticket",
            "dr exercise",
        ),
    ),
    (
        "backup_evidence_missing",
        "moderate",
        (
            "backup evidence",
            "snapshot evidence",
            "ami backup",
            "ami snapshot",
            "rds snapshot",
            "backup execution log",
        ),
    ),
    # ----- IAM / identity --------------------------------------------------
    (
        "password_policy_evidence_missing",
        "moderate",
        (
            "password policy",
            "ia-5",
            "complexity policy",
            "minimum password length",
        ),
    ),
    (
        "identity_listing_missing",
        "high",
        (
            "iam user list",
            "iam user listing",
            "account listing",
            "user listing",
            "privileged account",
            "service account inventory",
            "mfa report",
            "access review",
            "least privilege review",
            "iam role inventory",
        ),
    ),
    # ----- crypto / FIPS ---------------------------------------------------
    (
        "crypto_fips_evidence_missing",
        "high",
        (
            "fips 140",
            "fips-140",
            "fips validated",
            "fips validation",
            "crypto module",
            "kms key rotation",
            "key rotation",
            "cipher list",
            "tls cipher",
            "encryption at rest",
            "encryption in transit",
            "certificate inventory",
        ),
    ),
    # ----- traffic / boundary ----------------------------------------------
    (
        "traffic_flow_policy_missing",
        "high",
        (
            "traffic flow",
            "data flow diagram",
            "security group inventory",
            "security group",
            "ingress rule",
            "egress rule",
            "ports and protocols",
            "ports-and-protocols",
            "boundary diagram",
            "0.0.0.0/0",
            "administrative ports",
        ),
    ),
)


PHRASE_RULES: tuple[tuple[GapType, GapSeverity, tuple[str, ...]], ...] = _GAP_RULES


# ---------------------------------------------------------------------------
# POA&M-required heuristic
# ---------------------------------------------------------------------------

# These gap types ALWAYS require a POA&M row when they remain open at acceptance.
_POAM_REQUIRED_TYPES: frozenset[GapType] = frozenset(
    {
        "exploitation_review_missing",
        "poam_update_missing",
        "deviation_request_missing",
        "scanner_scope_missing",
        "vulnerability_scan_evidence_missing",
        "credentialed_scan_evidence_missing",
        "centralized_log_missing",
        "local_to_central_log_correlation_missing",
        "alert_rule_missing",
        "alert_sample_missing",
        "response_action_missing",
        "change_ticket_missing",
        "sia_missing",
        "approval_missing",
        "deployment_evidence_missing",
        "verification_evidence_missing",
        "restore_test_missing",
    }
)

_HIGH_RISK_CONTROL_PATTERNS = (
    re.compile(r"\bRA-5\(8\)"),
    re.compile(r"\bAU-12\b"),
    re.compile(r"\bSI-4\(4\)"),
    re.compile(r"\bAC-2\(7\)"),
    re.compile(r"\bIR-4\(3\)"),
    re.compile(r"\bCP-9\b"),
)


def _bump_severity_for_controls(controls: list[str], severity: GapSeverity) -> GapSeverity:
    blob = " ".join(controls)
    if any(p.search(blob) for p in _HIGH_RISK_CONTROL_PATTERNS) and severity == "moderate":
        return "high"
    return severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_tracker_gap(
    *,
    request_text: str,
    assessor_comment: str | None = None,
    csp_comment: str | None = None,
    controls: list[str] | None = None,
) -> GapClassification:
    """Return the structured :class:`GapClassification` for a tracker row's text.

    Concatenates ``request_text`` + ``assessor_comment`` + ``csp_comment`` and matches
    against :data:`_GAP_RULES` in order. First-match wins. Falls back to ``unknown``
    when no rule fires (the orchestrator decides what to do with that — typically
    creates an :class:`InformationalTrackerItem` rather than an :class:`EvidenceGap`).
    """
    haystack = " ".join(filter(None, [request_text, assessor_comment, csp_comment])).lower().strip()
    if not haystack:
        return GapClassification(
            gap_type="unknown",
            severity="low",
            recommended_artifact=None,
            recommended_validation=None,
            matched_phrases=[],
            poam_required=False,
        )

    for gap_type, severity, phrases in _GAP_RULES:
        matched = [p for p in phrases if p in haystack]
        if matched:
            sev = _bump_severity_for_controls(controls or [], severity)
            return GapClassification(
                gap_type=gap_type,
                severity=sev,
                recommended_artifact=_RECOMMENDED_ARTIFACTS.get(gap_type),
                recommended_validation=_RECOMMENDED_VALIDATIONS.get(gap_type),
                matched_phrases=matched,
                poam_required=gap_type in _POAM_REQUIRED_TYPES,
            )

    return GapClassification(
        gap_type="unknown",
        severity="low",
        recommended_artifact=None,
        recommended_validation=None,
        matched_phrases=[],
        poam_required=False,
    )
