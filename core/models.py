"""
Canonical provider-neutral security evidence models.

Pipeline/runtime glue (fixture bundles, correlation runs) lives in `core.pipeline_models`.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T", bound=BaseModel)

# --- Semantic types for SecurityEvent (closed set + unknown) ---

SemanticType = Literal[
    "identity.user_created",
    "identity.user_disabled",
    "identity.admin_role_granted",
    "identity.permission_changed",
    "identity.mfa_disabled",
    "network.public_admin_port_opened",
    "network.public_database_port_opened",
    "network.public_sensitive_service_opened",
    "network.firewall_rule_changed",
    "storage.policy_changed",
    "logging.audit_disabled",
    "logging.central_ingestion_missing",
    "compute.untracked_asset_created",
    "scanner.high_vulnerability_detected",
    "scanner.asset_missing_from_scope",
    "change.no_ticket_linked",
    "incident.no_response_evidence",
    "unknown",
]

AssetType = Literal[
    "compute",
    "database",
    "storage",
    "load_balancer",
    "network",
    "identity",
    "container",
    "unknown",
]

Criticality = Literal["low", "moderate", "high"]

Environment = Literal["dev", "test", "stage", "prod", "unknown"]

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]

FindingStatus = Literal["open", "closed", "accepted", "false_positive", "unknown"]

LogSourceType = Literal[
    "os_auth",
    "app_audit",
    "cloud_control_plane",
    "network_flow",
    "db_audit",
    "waf",
    "vulnerability_scanner",
    "idps",
    "unknown",
]

CentralDestination = Literal[
    "splunk",
    "sentinel",
    "chronicle",
    "cloudwatch",
    "log_analytics",
    "cloud_logging",
    "elastic",
    "none",
]

LogSourceStatus = Literal["active", "stale", "missing", "unknown"]

TicketSystem = Literal["jira", "servicenow", "github", "manual", "unknown"]

EvalOutcome = Literal["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE"]


class Asset(BaseModel):
    """
    Discovered workload or resource (provider-neutral).

    ``account_id`` / ``project_id`` / ``subscription_id`` / ``region`` are optional cloud scope hints
    (AWS account, GCP project, Azure subscription, region name)—not AWS-specific fields. Use ``tags``
    and ``raw_ref`` for vendor-specific metadata when needed.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    asset_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    account_id: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    region: str | None = None
    asset_type: AssetType
    name: str = Field(..., min_length=1)
    private_ips: list[str] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    criticality: Criticality
    environment: Environment
    raw_ref: str | None = None


class DeclaredInventoryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    inventory_id: str = Field(..., min_length=1)
    asset_id: str | None = None
    name: str = Field(..., min_length=1)
    asset_type: str = Field(..., min_length=1)
    expected_provider: str | None = None
    expected_region: str | None = None
    expected_private_ip: str | None = None
    expected_public_ip: str | None = None
    in_boundary: bool
    scanner_required: bool
    log_required: bool
    owner: str | None = None
    system_component: str | None = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    semantic_type: SemanticType
    timestamp: datetime
    actor: str | None = None
    asset_id: str | None = None
    resource_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    raw_event_name: str | None = None
    raw_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScannerTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scanner_name: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    target_type: str = Field(..., min_length=1)
    hostname: str | None = None
    ip: str | None = None
    asset_id: str | None = None
    scan_profile: str | None = None
    credentialed: bool
    last_scan_time: datetime | None = None


class ScannerFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    finding_id: str = Field(..., min_length=1)
    scanner_name: str = Field(..., min_length=1)
    asset_id: str | None = None
    target_id: str | None = None
    severity: FindingSeverity
    title: str = Field(..., min_length=1)
    cve_ids: list[str] = Field(default_factory=list)
    plugin_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: FindingStatus
    evidence: str = Field(..., min_length=1)
    raw_ref: str | None = None
    exploitation_review: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Provider-specific fields (Prowler check/compliance, OCSF class_uid, ElectricEye-style hints, "
            "import_extras). OCSF-like re-exports may mirror semantic typing under metadata.extensions."
        ),
    )


class LogSource(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    log_source_id: str = Field(..., min_length=1)
    asset_id: str | None = None
    source_type: LogSourceType
    local_source: str | None = None
    central_destination: CentralDestination | None = None
    last_seen: datetime | None = None
    status: LogSourceStatus
    sample_local_event_ref: str | None = None
    sample_central_event_ref: str | None = None


class AlertRule(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rule_id: str = Field(..., min_length=1)
    platform: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    enabled: bool
    mapped_semantic_types: list[str] = Field(default_factory=list)
    recipients: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    last_fired: datetime | None = None
    sample_alert_ref: str | None = None


class Ticket(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ticket_id: str = Field(..., min_length=1)
    system: TicketSystem
    title: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    linked_asset_ids: list[str] = Field(default_factory=list)
    linked_event_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)
    has_security_impact_analysis: bool
    has_testing_evidence: bool
    has_approval: bool
    has_deployment_evidence: bool
    has_verification_evidence: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None


class PoamItem(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    poam_id: str = Field(..., min_length=1)
    controls: list[str] = Field(default_factory=list)
    weakness_name: str = Field(..., min_length=1)
    weakness_description: str = Field(..., min_length=1)
    asset_identifier: str = Field(..., min_length=1)
    raw_severity: str = Field(..., min_length=1)
    adjusted_risk_rating: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    planned_remediation: str = Field(..., min_length=1)
    milestone_due_date: date | None = None
    source_eval_id: str | None = None


class EvalResult(BaseModel):
    """Single evaluation outcome against loaded evidence (canonical)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    eval_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    result: EvalOutcome
    controls: list[str] = Field(default_factory=list)
    severity: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    evidence: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    generated_artifacts: list[str] = Field(default_factory=list)


class AssessmentBundle(BaseModel):
    """Fully normalized assessment inputs — provider adapters populate this structure."""

    model_config = ConfigDict(extra="forbid")

    assets: list[Asset] = Field(default_factory=list)
    declared_inventory: list[DeclaredInventoryRecord] = Field(default_factory=list)
    events: list[SecurityEvent] = Field(default_factory=list)
    scanner_targets: list[ScannerTarget] = Field(default_factory=list)
    scanner_findings: list[ScannerFinding] = Field(default_factory=list)
    log_sources: list[LogSource] = Field(default_factory=list)
    alert_rules: list[AlertRule] = Field(default_factory=list)
    tickets: list[Ticket] = Field(default_factory=list)
    poam_items: list[PoamItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence gap models (assessment-tracker → structured gap)
# ---------------------------------------------------------------------------

GapType = Literal[
    "inventory_mismatch",
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
    "testing_evidence_missing",
    "approval_missing",
    "deployment_evidence_missing",
    "verification_evidence_missing",
    "exploitation_review_missing",
    "poam_update_missing",
    "deviation_request_missing",
    "backup_evidence_missing",
    "restore_test_missing",
    "identity_listing_missing",
    "password_policy_evidence_missing",
    "crypto_fips_evidence_missing",
    "traffic_flow_policy_missing",
    "unknown",
]

GapSeverity = Literal["low", "moderate", "high", "critical"]


class EvidenceGap(BaseModel):
    """Structured assessor-evidence-request gap derived from a tracker row.

    A gap is the *absence* of evidence that has been formally requested but has not yet
    been satisfied. It is not a finding (which is observed weakness in the system) — it is
    a contract about what the CSP must produce. Each gap is fully traceable back to its
    source tracker row.
    """

    model_config = ConfigDict(extra="forbid")

    gap_id: str = Field(..., min_length=1)
    source_item_id: str = Field(..., min_length=1)
    source_file: str = Field(..., min_length=1)
    controls: list[str] = Field(default_factory=list)
    gap_type: GapType
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    assessor_comment: str | None = None
    csp_comment: str | None = None
    owner: str | None = None
    status: str | None = None
    due_date: str | None = None
    severity: GapSeverity = "moderate"
    linked_ksi_ids: list[str] = Field(default_factory=list)
    recommended_artifact: str | None = None
    recommended_validation: str | None = None
    poam_required: bool = False


class InformationalTrackerItem(BaseModel):
    """A tracker row that does NOT represent an open evidence gap.

    Closed/satisfied/withdrawn rows still need to be accounted for so the assessor can
    audit the chain from request to closure. They never become :class:`EvidenceGap`
    records but are preserved here so no row is silently dropped.
    """

    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(..., min_length=1)
    source_item_id: str = Field(..., min_length=1)
    source_file: str = Field(..., min_length=1)
    controls: list[str] = Field(default_factory=list)
    title: str = Field(..., min_length=1)
    status: str | None = None
    owner: str | None = None
    reason_not_a_gap: str = Field(..., min_length=1)
    csp_comment: str | None = None
    assessor_comment: str | None = None


# --- JSON serialization helpers ---


def model_to_json(model: BaseModel, *, indent: int | None = 2) -> str:
    """Serialize any canonical model to JSON (datetime/date ISO-encoded)."""
    return model.model_dump_json(indent=indent)


def model_from_json(cls: type[T], data: str | bytes) -> T:
    """Strict parse of JSON into model class."""
    if isinstance(data, bytes):
        text = data.decode("utf-8")
    else:
        text = data
    return cls.model_validate_json(text)


def assessment_bundle_to_json(bundle: AssessmentBundle, *, indent: int | None = 2) -> str:
    return bundle.model_dump_json(indent=indent)


def assessment_bundle_from_json(data: str | bytes) -> AssessmentBundle:
    return model_from_json(AssessmentBundle, data)


def model_to_python_dict(model: BaseModel) -> dict[str, Any]:
    """JSON-compatible dict (ISO datetimes)."""
    return json.loads(model.model_dump_json())
