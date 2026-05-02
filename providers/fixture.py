"""Fixture-backed :class:`CloudProviderAdapter` — CSV/JSON scenarios to canonical models."""

from __future__ import annotations

import csv
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.models import (
    AlertRule,
    AssessmentBundle,
    Asset,
    CentralDestination,
    DeclaredInventoryRecord,
    LogSource,
    LogSourceStatus,
    LogSourceType,
    PoamItem,
    ScannerFinding,
    ScannerTarget,
    SecurityEvent,
    SemanticType,
    Ticket,
    TicketSystem,
)
from core.normalizer import normalize_cloud_event
from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle
from core.pipeline_models import PipelineSemanticEvent as PipelineSemanticEvent
from core.utils import load_csv_rows, load_evidence_bundle_from_directory, validate_evidence_bundle_minimum
from providers.base import CloudProviderAdapter

_TRUE = frozenset({"true", "1", "yes", "y", "t"})


class FixtureParseError(ValueError):
    """Raised when fixture files exist but cannot be parsed into canonical models."""

    def __init__(self, message: str, *, path: Path | None = None, cause: Exception | None = None) -> None:
        self.path = path
        self.__cause__ = cause
        loc = f" ({path})" if path else ""
        super().__init__(f"{message}{loc}")


def parse_bool(value: Any) -> bool:
    """Parse CSV / JSON boolean-ish values."""
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return False
    return str(value).strip().lower() in _TRUE


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value or not str(value).strip():
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError as e:
        raise FixtureParseError(f"Invalid ISO datetime: {value!r}", cause=e) from e


def parse_iso_date(value: str | None) -> date | None:
    if not value or not str(value).strip():
        return None
    s = str(value).strip()[:10]
    try:
        return date.fromisoformat(s)
    except ValueError as e:
        raise FixtureParseError(f"Invalid ISO date: {value!r}", cause=e) from e


_SEMANTIC_ALLOWED: frozenset[str] = frozenset(
    {
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
    }
)


def coerce_semantic_type(value: str) -> SemanticType:
    if value in _SEMANTIC_ALLOWED:
        return value  # type: ignore[return-value]
    return "unknown"


_RESOURCE_TO_ASSET_TYPE: dict[str, str] = {
    "EC2": "compute",
    "RDS": "database",
    "ELB": "load_balancer",
    "ALB": "load_balancer",
    "S3": "storage",
    "EKS": "container",
    "IAM": "identity",
    "VPC": "network",
}


def _norm_criticality(raw: str | None) -> str:
    if not raw:
        return "moderate"
    s = str(raw).strip().lower()
    if s == "medium":
        return "moderate"
    if s in ("low", "moderate", "high"):
        return s
    return "moderate"


def _norm_environment(tags: dict[str, str]) -> str:
    env = (tags.get("Environment") or tags.get("environment") or "").strip().lower()
    if env in ("dev", "test", "stage", "prod"):
        return env
    return "unknown"


def _asset_from_discovered_row(row: dict[str, Any]) -> Asset:
    rt = str(row.get("resource_type") or "unknown").upper()
    atype = _RESOURCE_TO_ASSET_TYPE.get(rt, "unknown")
    if atype == "unknown" and rt:
        rt_lower = rt.lower()
        if rt_lower in ("ec2", "instance"):
            atype = "compute"
    tags = {str(k): str(v) for k, v in (row.get("tags") or {}).items()}
    priv = row.get("private_ip") or row.get("private_ips")
    pub = row.get("public_ip") or row.get("public_ips")
    private_ips = [priv] if isinstance(priv, str) and priv else ([] if not isinstance(priv, list) else [str(x) for x in priv])
    public_ips = [pub] if isinstance(pub, str) and pub else ([] if not isinstance(pub, list) else [str(x) for x in pub])
    name = str(row.get("name") or row.get("asset_id") or "unknown")
    try:
        return Asset(
            asset_id=str(row["asset_id"]),
            provider=str(row.get("provider") or "aws"),
            account_id=str(row.get("account")) if row.get("account") else None,
            region=str(row.get("region")) if row.get("region") else None,
            asset_type=atype,  # type: ignore[arg-type]
            name=name,
            private_ips=private_ips,
            public_ips=public_ips,
            tags=tags,
            criticality=_norm_criticality(row.get("criticality")),  # type: ignore[arg-type]
            environment=_norm_environment(tags),  # type: ignore[arg-type]
            raw_ref=str(row.get("resource_id")) if row.get("resource_id") else None,
        )
    except (KeyError, ValidationError) as e:
        raise FixtureParseError(f"Invalid discovered asset row: {row!r}", cause=e) from e


def _declared_from_row(row: dict[str, Any], path: Path) -> DeclaredInventoryRecord:
    try:
        inv_id = str(row.get("inventory_id") or row.get("asset_id") or "").strip()
        if not inv_id:
            raise FixtureParseError("declared_inventory row missing inventory_id and asset_id", path=path)
        return DeclaredInventoryRecord(
            inventory_id=inv_id,
            asset_id=(str(row["asset_id"]).strip() if row.get("asset_id") else None),
            name=str(row.get("name") or row.get("asset_id") or "unknown"),
            asset_type=str(row.get("asset_type") or "unknown"),
            expected_provider=(str(row["expected_provider"]).strip() if row.get("expected_provider") else None),
            expected_region=(str(row["expected_region"]).strip() if row.get("expected_region") else None),
            expected_private_ip=(str(row["expected_private_ip"]).strip() if row.get("expected_private_ip") else None),
            expected_public_ip=(str(row["expected_public_ip"]).strip() if row.get("expected_public_ip") else None),
            in_boundary=parse_bool(row.get("in_boundary", True)),
            scanner_required=parse_bool(row.get("scanner_required", True)),
            log_required=parse_bool(row.get("log_required", True)),
            owner=(str(row["owner"]).strip() if row.get("owner") else None),
            system_component=(str(row["system_component"]).strip() if row.get("system_component") else None),
        )
    except ValidationError as e:
        raise FixtureParseError(f"Invalid declared inventory row: {row!r}", path=path, cause=e) from e


def _log_source_status_from_row(row: dict[str, Any]) -> LogSourceStatus:
    if row.get("status") in ("active", "stale", "missing", "unknown"):
        return row["status"]  # type: ignore[return-value]
    seen = parse_bool(row.get("seen_last_24h"))
    local = parse_bool(row.get("local_only"))
    if seen and not local:
        return "active"
    if local and not seen:
        return "stale"
    if not seen and not local:
        return "missing"
    return "unknown"


def _log_source_type(val: str | None) -> LogSourceType:
    s = (val or "unknown").strip().lower()
    allowed: set[str] = {
        "os_auth",
        "app_audit",
        "cloud_control_plane",
        "network_flow",
        "db_audit",
        "waf",
        "vulnerability_scanner",
        "idps",
        "unknown",
    }
    return s if s in allowed else "unknown"  # type: ignore[return-value]


def _central_destination(val: str | None) -> CentralDestination | None:
    if not val or str(val).strip().lower() in ("", "none"):
        return None
    s = str(val).strip().lower()
    allowed = frozenset(
        {"splunk", "sentinel", "chronicle", "cloudwatch", "log_analytics", "cloud_logging", "elastic", "none"}
    )
    if s in allowed and s != "none":
        return s  # type: ignore[return-value]
    return None


def _security_event_from_pipeline_semantic(sem: PipelineSemanticEvent, index: int) -> SecurityEvent:
    ts_raw = sem.timestamp or "1970-01-01T00:00:00Z"
    ts = parse_iso_datetime(ts_raw)
    if ts is None:
        ts = datetime(1970, 1, 1, tzinfo=None)
    st = coerce_semantic_type(sem.event_type)
    return SecurityEvent(
        event_id=sem.raw_event_ref or f"evt-{index}",
        provider=sem.provider,
        semantic_type=st,
        timestamp=ts,
        actor=sem.actor,
        asset_id=sem.asset_id if sem.asset_id != "unknown-asset" else None,
        resource_id=sem.resource_id,
        port=sem.port,
        raw_event_name=sem.metadata.get("eventName") if isinstance(sem.metadata, dict) else None,
        raw_ref=sem.raw_event_ref,
        metadata=dict(sem.metadata) if sem.metadata else {},
    )


def _security_events_from_cloud_events(pb: EvidenceBundle) -> list[SecurityEvent]:
    root = pb.source_root
    raw = pb.cloud_events
    items = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
    out: list[SecurityEvent] = []
    for i, e in enumerate(items):
        if not isinstance(e, dict):
            continue
        ref = f"{root / 'cloud_events.json'}#{i}"
        if e.get("_format") == "aws_cloudtrail":
            try:
                sem = normalize_cloud_event(e, ref)
                out.append(_security_event_from_pipeline_semantic(sem, i))
            except (ValueError, KeyError, ValidationError) as ex:
                raise FixtureParseError(
                    f"Cannot normalize AWS CloudTrail event at index {i}",
                    path=root / "cloud_events.json",
                    cause=ex,
                ) from ex
            continue
        if e.get("event_type"):
            ts = parse_iso_datetime(e.get("timestamp"))
            if ts is None:
                raise FixtureParseError(
                    f"Semantic event at index {i} requires valid timestamp",
                    path=root / "cloud_events.json",
                )
            st = coerce_semantic_type(str(e["event_type"]))
            out.append(
                SecurityEvent(
                    event_id=str(e.get("raw_event_ref") or f"evt-{i}"),
                    provider=str(e.get("provider") or "aws"),
                    semantic_type=st,
                    timestamp=ts,
                    actor=e.get("actor"),
                    asset_id=e.get("asset_id"),
                    resource_id=e.get("resource_id"),
                    port=e.get("port"),
                    raw_ref=e.get("raw_event_ref"),
                    metadata={k: v for k, v in e.items() if k not in {"event_type", "provider", "timestamp"}},
                )
            )
            continue
        if e.get("record_type") == "supporting_cloudtrail":
            detail = e.get("detail") or {}
            et = detail.get("eventTime") or "1970-01-01T00:00:00Z"
            ts = parse_iso_datetime(str(et))
            if ts is None:
                ts = datetime(1970, 1, 1)
            en = str(detail.get("eventName") or "unknown")
            out.append(
                SecurityEvent(
                    event_id=f"support-{i}-{re.sub(r'[^a-zA-Z0-9_-]+', '-', en)}",
                    provider="aws",
                    semantic_type="unknown",
                    timestamp=ts,
                    raw_event_name=en,
                    raw_ref=ref,
                    metadata={"supporting_cloudtrail": True},
                )
            )
    return out


def assessment_bundle_from_evidence_bundle(pb: EvidenceBundle) -> AssessmentBundle:
    """Convert on-disk pipeline evidence bundle to canonical :class:`AssessmentBundle`."""
    root = pb.source_root
    declared: list[DeclaredInventoryRecord] = []
    inv_path = root / "declared_inventory.csv"
    for row in pb.declared_inventory_rows:
        try:
            declared.append(_declared_from_row(row, inv_path))
        except FixtureParseError:
            raise
        except ValidationError as e:
            raise FixtureParseError(f"Declared inventory validation failed: {row!r}", path=inv_path, cause=e) from e

    assets_raw = pb.discovered_assets.get("assets", pb.discovered_assets.get("items", []))
    if not isinstance(assets_raw, list):
        assets_raw = []
    assets: list[Asset] = []
    for row in assets_raw:
        if isinstance(row, dict):
            assets.append(_asset_from_discovered_row(row))

    events = _security_events_from_cloud_events(pb)

    targets: list[ScannerTarget] = []
    for row in pb.scanner_target_rows:
        try:
            lst = row.get("last_scan_time")
            targets.append(
                ScannerTarget(
                    scanner_name=str(row.get("scanner") or row.get("scanner_name") or "unknown"),
                    target_id=str(row.get("target_id") or row.get("asset_id") or row.get("ip") or "unknown"),
                    target_type=str(row.get("target_type") or "host"),
                    hostname=(str(row["hostname"]).strip() if row.get("hostname") else None),
                    ip=(str(row["ip"]).strip() if row.get("ip") else None),
                    asset_id=(str(row["asset_id"]).strip() if row.get("asset_id") else None),
                    scan_profile=(str(row["scan_profile"]).strip() if row.get("scan_profile") else None),
                    credentialed=parse_bool(row.get("credentialed", False)),
                    last_scan_time=parse_iso_datetime(str(lst)) if lst else None,
                )
            )
        except ValidationError as e:
            raise FixtureParseError(f"Invalid scanner target row: {row!r}", path=root / "scanner_targets.csv", cause=e) from e

    findings_data = pb.scanner_findings.get("findings", pb.scanner_findings)
    if not isinstance(findings_data, list):
        findings_data = []
    default_scanner = str(pb.scanner_findings.get("scanner", "nessus"))
    findings: list[ScannerFinding] = []
    for row in findings_data:
        if not isinstance(row, dict):
            continue
        cve_raw = row.get("cve_ids") or row.get("cve") or []
        if isinstance(cve_raw, str):
            cve_ids = [cve_raw] if cve_raw else []
        else:
            cve_ids = [str(x) for x in cve_raw]
        sev = str(row.get("severity", "info")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        st = str(row.get("status", "unknown")).lower()
        if st not in ("open", "closed", "accepted", "false_positive", "unknown"):
            st = "unknown"
        try:
            findings.append(
                ScannerFinding(
                    finding_id=str(row.get("finding_id") or row.get("plugin_id") or "unknown"),
                    scanner_name=str(row.get("scanner_name") or default_scanner),
                    asset_id=(str(row["asset_id"]).strip() if row.get("asset_id") else None),
                    target_id=(str(row["target_id"]).strip() if row.get("target_id") else None),
                    severity=sev,  # type: ignore[arg-type]
                    title=str(row.get("title") or "Finding"),
                    cve_ids=cve_ids,
                    plugin_id=(str(row["plugin_id"]).strip() if row.get("plugin_id") else None),
                    first_seen=parse_iso_datetime(str(row["first_seen"])) if row.get("first_seen") else None,
                    last_seen=parse_iso_datetime(str(row["last_seen"])) if row.get("last_seen") else None,
                    status=st,  # type: ignore[arg-type]
                    evidence=str(row.get("evidence") or row.get("title") or "."),
                    raw_ref=(str(row["raw_ref"]).strip() if row.get("raw_ref") else None),
                    exploitation_review=dict(row["exploitation_review"])
                    if isinstance(row.get("exploitation_review"), dict)
                    else {},
                    metadata=dict(row["metadata"]) if isinstance(row.get("metadata"), dict) else {},
                )
            )
        except ValidationError as e:
            raise FixtureParseError(f"Invalid scanner finding: {row!r}", path=root / "scanner_findings.json", cause=e) from e

    log_sources: list[LogSource] = []
    src_block = pb.central_log_sources.get("sources", pb.central_log_sources)
    if not isinstance(src_block, list):
        src_block = []
    for row in src_block:
        if not isinstance(row, dict):
            continue
        lid = str(row.get("log_source_id") or row.get("name") or "log-source")
        cd = row.get("central_destination")
        try:
            log_sources.append(
                LogSource(
                    log_source_id=lid,
                    asset_id=(str(row["asset_id"]).strip() if row.get("asset_id") else None),
                    source_type=_log_source_type(row.get("source_type")),
                    local_source=(str(row["local_source"]).strip() if row.get("local_source") else None),
                    central_destination=_central_destination(str(cd) if cd is not None else None),
                    last_seen=parse_iso_datetime(str(row["last_seen"])) if row.get("last_seen") else None,
                    status=_log_source_status_from_row(row),
                    sample_local_event_ref=(str(row["sample_local_event_ref"]).strip() if row.get("sample_local_event_ref") else None),
                    sample_central_event_ref=(str(row["sample_central_event_ref"]).strip() if row.get("sample_central_event_ref") else None),
                )
            )
        except ValidationError as e:
            raise FixtureParseError(
                f"Invalid log source row: {row!r}", path=root / "central_log_sources.json", cause=e
            ) from e

    rules_block = pb.alert_rules.get("rules", pb.alert_rules)
    if not isinstance(rules_block, list):
        rules_block = []
    platform_default = str(pb.alert_rules.get("platform", "splunk"))
    alert_rules: list[AlertRule] = []
    for row in rules_block:
        if not isinstance(row, dict):
            continue
        mapped = list(row.get("mapped_semantic_types") or [])
        et = row.get("event_types") or []
        if isinstance(et, str):
            et = [et]
        for x in et:
            if x and x not in mapped:
                mapped.append(str(x))
        mt = row.get("matches_event_type")
        if mt and mt not in mapped:
            mapped.append(str(mt))
        rec = row.get("recipients") or []
        if isinstance(rec, str):
            rec = [rec]
        ctrl = row.get("controls") or []
        if isinstance(ctrl, str):
            ctrl = [c.strip() for c in str(ctrl).split(",") if c.strip()]
        rid = str(row.get("rule_id") or row.get("name") or "rule").replace(" ", "-").lower()
        try:
            alert_rules.append(
                AlertRule(
                    rule_id=rid,
                    platform=str(row.get("platform") or platform_default),
                    name=str(row.get("name") or rid),
                    enabled=parse_bool(row.get("enabled", False)),
                    mapped_semantic_types=[str(x) for x in mapped],
                    recipients=[str(x) for x in rec],
                    controls=[str(x) for x in ctrl],
                    last_fired=parse_iso_datetime(str(row["last_fired"])) if row.get("last_fired") else None,
                    sample_alert_ref=(str(row["sample_alert_ref"]).strip() if row.get("sample_alert_ref") else None),
                )
            )
        except ValidationError as e:
            raise FixtureParseError(f"Invalid alert rule: {row!r}", path=root / "alert_rules.json", cause=e) from e

    tickets_out: list[Ticket] = []
    tix = pb.tickets.get("tickets", pb.tickets)
    if not isinstance(tix, list):
        tix = []
    system_default: TicketSystem = "jira"
    sys_raw = pb.tickets.get("system") if isinstance(pb.tickets, dict) else None
    if isinstance(sys_raw, str) and sys_raw.lower() in ("jira", "servicenow", "github", "manual", "unknown"):
        system_default = sys_raw.lower()  # type: ignore[assignment]
    for row in tix:
        if not isinstance(row, dict):
            continue
        la: list[str] = []
        aid = row.get("links_asset_id")
        if aid and str(aid).strip():
            la.append(str(aid).strip())
        le: list[str] = []
        ref = row.get("links_event_ref")
        if ref and str(ref).strip():
            le.append(str(ref).strip())
        lf: list[str] = []
        lfid = row.get("linked_finding_ids")
        if isinstance(lfid, list):
            lf.extend(str(x) for x in lfid)
        elif lfid:
            lf.append(str(lfid))
        has_dep = row.get("has_deployment_evidence")
        if has_dep is None:
            has_dep = row.get("deployment_recorded")
        has_ver = row.get("has_verification_evidence")
        if has_ver is None:
            has_ver = row.get("post_deploy_verification")
        try:
            tickets_out.append(
                Ticket(
                    ticket_id=str(row.get("id") or row.get("ticket_id") or "UNKNOWN"),
                    system=system_default,
                    title=str(row.get("title") or "Ticket"),
                    status=str(row.get("status") or "unknown"),
                    linked_asset_ids=la,
                    linked_event_ids=le,
                    linked_finding_ids=lf,
                    has_security_impact_analysis=parse_bool(row.get("security_impact_analysis")),
                    has_testing_evidence=parse_bool(row.get("test_evidence")),
                    has_approval=parse_bool(row.get("approval_recorded")),
                    has_deployment_evidence=parse_bool(has_dep),
                    has_verification_evidence=parse_bool(has_ver),
                    created_at=parse_iso_datetime(str(row["created_at"])) if row.get("created_at") else None,
                    updated_at=parse_iso_datetime(str(row["updated_at"])) if row.get("updated_at") else None,
                    closed_at=parse_iso_datetime(str(row["closed_at"])) if row.get("closed_at") else None,
                )
            )
        except ValidationError as e:
            raise FixtureParseError(f"Invalid ticket row: {row!r}", path=root / "tickets.json", cause=e) from e

    poam_items: list[PoamItem] = []
    for row in pb.poam_seed_rows:
        if not row:
            continue
        ctrl_raw = row.get("controls") or ""
        controls = [c.strip() for c in str(ctrl_raw).replace(";", ",").split(",") if c.strip()]
        wn = str(row.get("weakness_name") or "weakness")
        notes = str(row.get("notes") or row.get("weakness_description") or wn)
        raw_sev = str(row.get("raw_severity") or "moderate").lower()
        adj = str(row.get("adjusted_risk_rating") or raw_sev)
        try:
            poam_items.append(
                PoamItem(
                    poam_id=str(row.get("poam_id") or "POAM-UNKNOWN"),
                    controls=controls,
                    weakness_name=wn,
                    weakness_description=notes,
                    asset_identifier=str(row.get("asset_identifier") or row.get("asset_id") or "unknown"),
                    raw_severity=raw_sev,
                    adjusted_risk_rating=adj,
                    status=str(row.get("status") or "open"),
                    planned_remediation=str(
                        row.get("planned_remediation") or row.get("milestones") or "Track per ISSO POA&M process."
                    ),
                    milestone_due_date=parse_iso_date(str(row["milestone_due_date"])) if row.get("milestone_due_date") else None,
                    source_eval_id=(str(row["source_eval_id"]).strip() if row.get("source_eval_id") else None),
                )
            )
        except ValidationError as e:
            raise FixtureParseError(f"Invalid POA&M row: {row!r}", path=root / "poam.csv", cause=e) from e

    return AssessmentBundle(
        assets=assets,
        declared_inventory=declared,
        events=events,
        scanner_targets=targets,
        scanner_findings=findings,
        log_sources=log_sources,
        alert_rules=alert_rules,
        tickets=tickets_out,
        poam_items=poam_items,
    )


def _load_declared_rows_strict(path: Path) -> list[dict[str, Any]]:
    """Read declared_inventory.csv with clear errors on malformed CSV."""
    if not path.is_file():
        raise FileNotFoundError(f"Fixture scenario is missing required file: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise FixtureParseError(f"Cannot read declared inventory: {e}", path=path, cause=e) from e
    try:
        lines = text.strip().splitlines()
        if not lines:
            return []
        reader = csv.DictReader(lines)
        return [dict(r) for r in reader]
    except csv.Error as e:
        raise FixtureParseError(f"Malformed CSV in declared inventory: {e}", path=path, cause=e) from e


FIXTURE_CLOCK_FILENAME = "fixture_clock.json"

# Datetime fields per canonical model that opt into the fixture-clock anchor.
# When a scenario ships ``fixture_clock.json`` with an ``anchor`` ISO timestamp,
# every datetime listed here is shifted by ``(now - anchor)`` so the latest
# fixture event becomes "current" relative to wall-clock time. This keeps
# time-aware evaluators (e.g. AU-6 24h freshness) deterministic without
# hard-coding anything; opt-in only — scenarios without the file behave
# exactly as before.
_CLOCK_ANCHORED_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("events", ("timestamp",)),
    ("scanner_findings", ("first_seen", "last_seen")),
    ("scanner_targets", ("last_scan_time",)),
    ("log_sources", ("last_seen",)),
    ("alert_rules", ("last_fired",)),
    ("tickets", ("created_at", "updated_at", "closed_at")),
)


def _shift_dt(value: datetime | None, delta: timedelta) -> datetime | None:
    if value is None:
        return None
    return value + delta


def _apply_fixture_clock_anchor(
    bundle: AssessmentBundle,
    *,
    anchor: datetime,
    now: datetime | None = None,
) -> AssessmentBundle:
    """Shift every datetime field in *bundle* by ``(now - anchor)``.

    The shift is applied **only** when ``anchor`` is non-trivially old (more
    than 12 hours behind ``now``); otherwise the bundle is returned unchanged.
    This guarantees that re-running the same fixture in the same hour produces
    the identical bundle (no flapping).

    Returns the same ``bundle`` instance (Pydantic models are mutated in place
    via ``setattr`` since their fields are not frozen).
    """
    now = now or datetime.now(tz=timezone.utc)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    delta = now - anchor
    if delta < timedelta(hours=12):
        return bundle  # already fresh enough; do not perturb
    # Subtract a small offset so the latest event reads as "now - 60s" rather
    # than exactly "now"; avoids pathological "future" timestamps if the
    # evaluator runs on a slightly slower clock than the wall clock.
    delta -= timedelta(seconds=60)
    for field, dt_attrs in _CLOCK_ANCHORED_FIELDS:
        items = getattr(bundle, field, None) or []
        for item in items:
            for attr in dt_attrs:
                if not hasattr(item, attr):
                    continue
                cur = getattr(item, attr)
                if isinstance(cur, datetime):
                    setattr(item, attr, _shift_dt(cur, delta))
    return bundle


def _shift_iso_string(s: str | None, delta: timedelta) -> str | None:
    """Best-effort shift of an ISO-8601 timestamp string by *delta*.

    Returns the input untouched if it can't be parsed (so non-timestamp
    values are safe to feed in).
    """
    if not s or not isinstance(s, str):
        return s
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    out = dt + delta
    # Re-emit as RFC-3339-compatible UTC with Z suffix when input had Z.
    iso = out.astimezone(timezone.utc).isoformat()
    if s.endswith("Z"):
        iso = iso.replace("+00:00", "Z")
    return iso


# Pipeline-bundle dict paths that carry timestamps. Each entry is
# (top-level attribute, list-key inside that attribute or None, list of dict
# keys to shift). When list-key is None we expect the attribute itself to be
# a list of dicts.
_PIPELINE_DICT_PATHS: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
    ("central_log_sources", "sources", ("last_seen",)),
    ("scanner_findings",    "findings", ("first_seen", "last_seen")),
    ("alert_rules",         "rules", ("last_fired",)),
    ("tickets",             "tickets", ("created_at", "updated_at", "closed_at")),
    ("scanner_target_rows", None, ("last_scan_time",)),
)


def _apply_fixture_clock_anchor_to_pipeline(
    pipeline: EvidenceBundle,
    *,
    anchor: datetime,
    now: datetime | None = None,
) -> EvidenceBundle:
    """Shift every known timestamp string in the legacy pipeline bundle.

    Mirrors :func:`_apply_fixture_clock_anchor` but operates on the raw
    dict-shaped bundle that is consumed directly by the eval pipeline
    (the canonical AssessmentBundle path uses the Pydantic helper above).
    """
    now = now or datetime.now(tz=timezone.utc)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    delta = now - anchor
    if delta < timedelta(hours=12):
        return pipeline
    delta -= timedelta(seconds=60)

    # --- Dict-shaped sub-bundles ---
    for attr, list_key, dt_keys in _PIPELINE_DICT_PATHS:
        block = getattr(pipeline, attr, None)
        if block is None:
            continue
        if list_key is None:
            items = block if isinstance(block, list) else []
        else:
            items = block.get(list_key) if isinstance(block, dict) else None
            if items is None:
                continue
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            for k in dt_keys:
                if k in it:
                    it[k] = _shift_iso_string(it.get(k), delta)

    # --- Cloud events: list of dicts with "timestamp" ---
    ce = getattr(pipeline, "cloud_events", None)
    if isinstance(ce, list):
        for ev in ce:
            if isinstance(ev, dict) and "timestamp" in ev:
                ev["timestamp"] = _shift_iso_string(ev.get("timestamp"), delta)
    elif isinstance(ce, dict):
        events = ce.get("events") or ce.get("items") or []
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict) and "timestamp" in ev:
                    ev["timestamp"] = _shift_iso_string(ev.get("timestamp"), delta)

    return pipeline


def _read_fixture_clock(scenario_root: Path) -> datetime | None:
    """Return the ``anchor`` datetime from ``fixture_clock.json`` if present.

    File schema (all fields optional except ``anchor``)::

        {
          "anchor": "2026-05-01T11:45:00Z",
          "comment": "human note about why this scenario is time-anchored"
        }
    """
    p = scenario_root / FIXTURE_CLOCK_FILENAME
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = data.get("anchor") if isinstance(data, dict) else None
    if not raw:
        return None
    try:
        # Normalize trailing Z to +00:00 for fromisoformat.
        s = str(raw).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class FixtureProvider(CloudProviderAdapter):
    """Loads a scenario directory into canonical models (and legacy pipeline bundle)."""

    REQUIRED = (
        "declared_inventory.csv",
        "discovered_assets.json",
        "cloud_events.json",
        "scanner_findings.json",
        "scanner_targets.csv",
        "central_log_sources.json",
        "alert_rules.json",
        "tickets.json",
    )

    def __init__(self, scenario_root: Path) -> None:
        self._root = scenario_root.resolve()
        self._pipeline: EvidenceBundle | None = None
        self._assessment: AssessmentBundle | None = None

    def validate_layout(self) -> None:
        missing = [name for name in self.REQUIRED if not (self._root / name).is_file()]
        if missing:
            rel = ", ".join(missing)
            raise FileNotFoundError(
                f"Fixture scenario at {self._root} is missing required file(s): {rel}. "
                f"Expected a complete layout including: {', '.join(self.REQUIRED)}."
            )

    def load(self) -> EvidenceBundle:
        """Legacy pipeline bundle (same on-disk layout as :meth:`load_bundle` source)."""
        return self._ensure_pipeline()

    def _ensure_pipeline(self) -> EvidenceBundle:
        if self._pipeline is None:
            self.validate_layout()
            try:
                self._pipeline = load_evidence_bundle_from_directory(self._root)
            except UnicodeDecodeError as e:
                raise FixtureParseError(
                    "Cannot decode scenario file as UTF-8 (declared_inventory.csv or other text)",
                    path=self._root,
                    cause=e,
                ) from e
            except csv.Error as e:
                raise FixtureParseError(
                    "Malformed CSV in scenario (check quoted fields and row shape)",
                    path=self._root / "declared_inventory.csv",
                    cause=e,
                ) from e
            except json.JSONDecodeError as e:
                raise FixtureParseError(
                    f"Invalid JSON in scenario: {e!s}",
                    path=self._root,
                    cause=e,
                ) from e
            anchor = _read_fixture_clock(self._root)
            if anchor is not None:
                self._pipeline = _apply_fixture_clock_anchor_to_pipeline(
                    self._pipeline, anchor=anchor
                )
            validate_evidence_bundle_minimum(self._pipeline)
        return self._pipeline

    def load_bundle(self) -> AssessmentBundle:
        if self._assessment is None:
            try:
                bundle = assessment_bundle_from_evidence_bundle(self._ensure_pipeline())
            except FixtureParseError:
                raise
            except ValidationError as e:
                raise FixtureParseError(
                    "Canonical model validation failed when parsing fixture",
                    path=self._root,
                    cause=e,
                ) from e
            anchor = _read_fixture_clock(self._root)
            if anchor is not None:
                bundle = _apply_fixture_clock_anchor(bundle, anchor=anchor)
            self._assessment = bundle
        return self._assessment

    def list_assets(self) -> list[Asset]:
        return list(self.load_bundle().assets)

    def list_events(self) -> list[SecurityEvent]:
        return list(self.load_bundle().events)

    def list_scanner_targets(self) -> list[ScannerTarget]:
        return list(self.load_bundle().scanner_targets)

    def list_scanner_findings(self) -> list[ScannerFinding]:
        return list(self.load_bundle().scanner_findings)

    def list_log_sources(self) -> list[LogSource]:
        return list(self.load_bundle().log_sources)

    def list_alert_rules(self) -> list[AlertRule]:
        return list(self.load_bundle().alert_rules)

    def list_tickets(self) -> list[Ticket]:
        return list(self.load_bundle().tickets)

    def list_poam_items(self) -> list[PoamItem]:
        return list(self.load_bundle().poam_items)

    def provider_name(self) -> str:
        return "fixture"
