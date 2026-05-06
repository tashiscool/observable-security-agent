"""AWS evidence: live collection helpers, pipeline bundle loader, and raw-json :class:`AWSProvider`."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from core.csv_utils import load_csv_rows
from core.models import (
    AlertRule,
    AssessmentBundle,
    Asset,
    CentralDestination,
    DeclaredInventoryRecord,
    LogSource,
    PoamItem,
    ScannerFinding,
    ScannerTarget,
    SecurityEvent,
    SemanticType,
    Ticket,
    TicketSystem,
)
from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle, PipelineSemanticEvent
from core.utils import load_evidence_bundle_from_directory, validate_evidence_bundle_minimum
from providers.base import CloudProviderAdapter
from providers.fixture import coerce_semantic_type, parse_bool, parse_iso_date, parse_iso_datetime
from providers.exposure_policy import (
    exposure_rank_for_semantic,
    iter_canonical_exposure_probe_ports,
    semantic_type_for_exposed_port,
)

# ---------------------------------------------------------------------------
# Parsing helpers (used by AWSProvider and tests)
# ---------------------------------------------------------------------------


def is_public_cidr(cidr: str | None) -> bool:
    if not cidr or not str(cidr).strip():
        return False
    return str(cidr).strip() in ("0.0.0.0/0", "::/0")


def is_admin_port(port: int) -> bool:
    return semantic_type_for_exposed_port(port, "tcp") == "network.public_admin_port_opened"


def is_database_port(port: int) -> bool:
    return semantic_type_for_exposed_port(port, "tcp") == "network.public_database_port_opened"


def extract_event_time(record: dict[str, Any]) -> datetime | None:
    for key in ("eventTime", "EventTime", "time", "timestamp"):
        v = record.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            continue
    return None


def extract_actor_from_cloudtrail(record: dict[str, Any]) -> str | None:
    ui = record.get("userIdentity")
    if not isinstance(ui, dict):
        return None
    ut = str(ui.get("type") or "")
    if ut == "IAMUser":
        return str(ui.get("userName") or ui.get("arn") or "").strip() or None
    if ut == "AssumedRole":
        ac = ui.get("sessionContext", {})
        if isinstance(ac, dict):
            issuer = ac.get("sessionIssuer", {})
            if isinstance(issuer, dict):
                return str(issuer.get("userName") or issuer.get("arn") or "").strip() or None
        return str(ui.get("arn") or "").strip() or None
    if ut == "Root":
        return "root"
    return str(ui.get("arn") or ui.get("principalId") or "").strip() or None


def _iter_ports(
    from_port: int | None, to_port: int | None, ip_protocol: str | None
) -> Iterator[tuple[int, str]]:
    """Yield ``(port, effective_protocol)`` for permissions expansion."""
    raw = (ip_protocol or "").lower()
    if raw in ("-1", "all"):
        for p in iter_canonical_exposure_probe_ports():
            yield p, "-1"
        return
    if raw in ("tcp", "6", ""):
        eff = "tcp"
    elif raw in ("udp", "17"):
        eff = "udp"
    elif raw in ("icmp", "1"):
        return
    else:
        eff = raw
    lo = int(from_port) if from_port is not None else 0
    hi = int(to_port) if to_port is not None else lo
    if hi < lo:
        lo, hi = hi, lo
    span = hi - lo + 1
    if span > 512:
        yield lo, eff
        return
    for p in range(lo, hi + 1):
        yield p, eff


def extract_security_group_exposures(sg: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return exposure rows for ``describe_security_groups`` one SG dict.

    Each row: ``group_id``, ``vpc_id``, ``port``, ``protocol``, ``cidr``, ``semantic_type`` (str).
    """
    gid = str(sg.get("GroupId") or "")
    vpc = str(sg.get("VpcId") or "")
    rows: list[dict[str, Any]] = []
    for perm in sg.get("IpPermissions") or []:
        if not isinstance(perm, dict):
            continue
        proto = str(perm.get("IpProtocol") or "")
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")
        ranges: list[str] = []
        for block in perm.get("IpRanges") or []:
            if isinstance(block, dict) and block.get("CidrIp"):
                ranges.append(str(block["CidrIp"]))
        for block in perm.get("Ipv6Ranges") or []:
            if isinstance(block, dict) and block.get("CidrIpv6"):
                ranges.append(str(block["CidrIpv6"]))
        for cidr in ranges:
            if not is_public_cidr(cidr):
                continue
            for port, eff_proto in _iter_ports(
                int(from_p) if from_p is not None else None,
                int(to_p) if to_p is not None else None,
                proto,
            ):
                sem = semantic_type_for_exposed_port(port, eff_proto)
                rows.append(
                    {
                        "group_id": gid,
                        "vpc_id": vpc,
                        "port": port,
                        "protocol": proto,
                        "cidr": cidr,
                        "semantic_type": sem,
                    }
                )
    return rows


def aws_cloudtrail_bundle_event_to_semantic(raw: dict[str, Any], ref_path: str) -> PipelineSemanticEvent:
    """
    Map a fixture- or export-shaped CloudTrail event (``_format == "aws_cloudtrail"``) to a pipeline semantic event.

    Lives in this module so :mod:`core.normalizer` stays provider-neutral; callers use lazy import to avoid cycles.
    """
    detail = raw.get("detail", {})
    req = detail.get("requestParameters", {}) or {}
    user_id = (
        detail.get("userIdentity", {}).get("userName")
        or detail.get("userIdentity", {}).get("arn", "").split("/")[-1]
        or "unknown"
    )
    sg = req.get("groupId") or req.get("group_id") or "unknown-sg"
    ip_ranges = req.get("ipPermissions", {}).get("items", []) if isinstance(
        req.get("ipPermissions"), dict
    ) else []
    port = 22
    source = "0.0.0.0/0"
    if ip_ranges:
        first = ip_ranges[0]
        rngs = first.get("ipRanges", {}).get("items", []) if isinstance(
            first.get("ipRanges"), dict
        ) else []
        if rngs and isinstance(rngs[0], dict):
            source = rngs[0].get("cidrIp") or source
        pr = first.get("fromPort")
        if pr is not None:
            port = int(pr)
    asset = raw.get("_asset_id") or "unknown-asset"
    st_ev: SemanticType = semantic_type_for_exposed_port(port, "tcp")
    return PipelineSemanticEvent(
        event_type=st_ev,
        provider="aws",
        actor=user_id if "@" in str(user_id) else f"{user_id}@example.com",
        asset_id=asset,
        resource_id=sg,
        timestamp=detail.get("eventTime") or raw.get("time", ""),
        raw_event_ref=ref_path,
        port=port,
        source_cidr=source,
        metadata={"eventName": detail.get("eventName"), "eventSource": detail.get("eventSource")},
    )


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


def _tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    if not tags:
        return {}
    return {str(t["Key"]): str(t["Value"]) for t in tags if isinstance(t, dict) and "Key" in t and "Value" in t}


def _asset_id_from_tags(tags: dict[str, str], fallback: str) -> str:
    return (
        tags.get("AssetId")
        or tags.get("asset_id")
        or tags.get("Name")
        or fallback
    )


def _parse_policy_doc(raw: Any) -> Any | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    s = str(raw).strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def _policy_json_admin_like(obj: Any) -> bool:
    """Heuristic: wildcard admin-style IAM policy."""
    if not isinstance(obj, dict):
        return False
    stm = obj.get("Statement")
    if not isinstance(stm, list):
        stm = [stm] if stm is not None else []
    for st in stm:
        if not isinstance(st, dict):
            continue
        effect = str(st.get("Effect", "")).lower()
        if effect != "allow":
            continue
        actions = st.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        resources = st.get("Resource")
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(resources, list):
            resources = []
        wide_action = any(str(a).strip() in ("*", "iam:*", "iam:PassRole") for a in actions)
        wide_res = any(str(r).strip() == "*" for r in resources) if resources else False
        if wide_action and wide_res:
            return True
    return False


def _policy_arn_is_admin(arn: str | None) -> bool:
    if not arn:
        return False
    a = str(arn).lower().replace("_", "")
    return "administratoraccess" in a or "arn:aws:iam::aws:policy/admin" in a


def _put_bucket_policy_public_heuristic(policy_text: str) -> bool:
    """Rough check for world principal / * in bucket policy string."""
    s = policy_text.lower()
    if '"principal":"*"' in s.replace(" ", "") or '"principal": "*"' in s:
        return True
    if "principal" in s and "*" in s and "allow" in s:
        return True
    return False


def semantic_type_from_cloudtrail_event(record: dict[str, Any]) -> tuple[SemanticType, dict[str, Any]]:
    """
    Map a CloudTrail-style record (top-level API fields) to semantic type + metadata.

    ``record`` may be the inner ``detail`` object for EventBridge-shaped payloads or full CT record.
    """
    meta: dict[str, Any] = {}
    en = str(record.get("eventName") or "")
    meta["eventName"] = en
    req = record.get("requestParameters") or {}
    if not isinstance(req, dict):
        req = {}

    if en == "AuthorizeSecurityGroupIngress":
        ip_perms = req.get("ipPermissions") or req.get("IpPermissions") or {}
        items = ip_perms.get("items") if isinstance(ip_perms, dict) else None
        if not isinstance(items, list):
            items = []
        worst: SemanticType = "network.firewall_rule_changed"
        worst_rank = exposure_rank_for_semantic(worst)
        for item in items:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("ipProtocol") or item.get("IpProtocol") or "tcp").lower()
            rngs = item.get("ipRanges") or item.get("IpRanges") or {}
            cidr_items = rngs.get("items") if isinstance(rngs, dict) else None
            if not isinstance(cidr_items, list):
                cidr_items = []
            v6 = item.get("ipv6Ranges") or item.get("Ipv6Ranges") or {}
            v6_items = v6.get("items") if isinstance(v6, dict) else None
            if not isinstance(v6_items, list):
                v6_items = []
            has_public = any(
                isinstance(cr, dict) and is_public_cidr(str(cr.get("cidrIp") or cr.get("CidrIp") or ""))
                for cr in cidr_items
            ) or any(
                isinstance(cr, dict) and is_public_cidr(str(cr.get("cidrIpv6") or cr.get("CidrIpv6") or ""))
                for cr in v6_items
            )
            if not has_public:
                continue
            if proto in ("-1", "all"):
                for port in iter_canonical_exposure_probe_ports():
                    st = semantic_type_for_exposed_port(port, "-1")
                    nr = exposure_rank_for_semantic(st)
                    if nr > worst_rank:
                        worst_rank = nr
                        worst = st
                continue
            try:
                fp = int(item.get("fromPort") or item.get("FromPort") or 0)
                tp = int(item.get("toPort") or item.get("ToPort") or fp)
            except (TypeError, ValueError):
                fp, tp = 0, 0
            for port in range(fp, tp + 1):
                st = semantic_type_for_exposed_port(port, proto)
                nr = exposure_rank_for_semantic(st)
                if nr > worst_rank:
                    worst_rank = nr
                    worst = st
        return worst, meta

    if en in ("RevokeSecurityGroupIngress", "CreateSecurityGroup", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress"):
        return "network.firewall_rule_changed", meta

    if en == "PutBucketPolicy":
        pol = req.get("bucketPolicy") or req.get("policy") or ""
        text = pol if isinstance(pol, str) else json.dumps(pol)
        if _put_bucket_policy_public_heuristic(text):
            return "storage.policy_changed", meta
        return "network.firewall_rule_changed", meta

    if en == "CreateUser":
        return "identity.user_created", meta
    if en == "DeleteUser":
        return "identity.user_disabled", meta

    if en in ("AttachUserPolicy", "AttachRolePolicy"):
        arn = req.get("policyArn") or req.get("PolicyArn")
        if _policy_arn_is_admin(str(arn) if arn else None):
            return "identity.admin_role_granted", meta
        return "identity.permission_changed", meta

    if en in ("PutUserPolicy", "PutRolePolicy"):
        doc = req.get("policyDocument") or req.get("PolicyDocument")
        parsed = _parse_policy_doc(doc)
        if _policy_arn_is_admin(str(req.get("policyArn") or "")):
            return "identity.admin_role_granted", meta
        if _policy_json_admin_like(parsed):
            return "identity.admin_role_granted", meta
        return "identity.permission_changed", meta

    if en in ("DeactivateMFADevice", "DeleteVirtualMFADevice"):
        return "identity.mfa_disabled", meta

    if en in ("StopLogging", "DeleteTrail"):
        return "logging.audit_disabled", meta

    if en == "UpdateTrail":
        if (
            req.get("enableLogging") is False
            or req.get("EnableLogging") is False
            or str(req.get("IsLogging", "")).lower() in ("false", "0")
        ):
            return "logging.audit_disabled", meta
        return "network.firewall_rule_changed", meta

    if en == "RunInstances":
        return "compute.untracked_asset_created", meta

    return "unknown", meta


def _read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _iter_ec2_pages(data: Any) -> Iterator[dict[str, Any]]:
    if isinstance(data, dict) and "Pages" in data:
        for p in data.get("Pages") or []:
            if isinstance(p, dict):
                yield p
    elif isinstance(data, dict):
        yield data


def _discover_region_roots(raw_evidence_dir: Path) -> list[Path]:
    """Return per-region raw directories (each contains ``identity/``, ``compute/``, …)."""
    base = raw_evidence_dir.resolve()
    aws = base / "raw" / "aws"
    if aws.is_dir():
        roots: list[Path] = []
        for acct in sorted(aws.iterdir()):
            if not acct.is_dir():
                continue
            for reg in sorted(acct.iterdir()):
                if reg.is_dir() and (reg / "identity").is_dir():
                    roots.append(reg)
        if roots:
            return roots
    if (base / "identity" / "sts_get_caller_identity.json").is_file():
        return [base]
    return []


def _resource_from_ct(record: dict[str, Any]) -> str | None:
    rp = record.get("requestParameters") or {}
    if isinstance(rp, dict):
        for k in ("groupId", "GroupId", "trailName", "TrailName", "bucketName", "BucketName", "userName", "UserName"):
            if rp.get(k):
                return str(rp[k])
    return str(record.get("resourcesAffected") or record.get("resourceId") or "") or None


def _iter_cloudtrail_like_records(obj: Any, source: Path) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield (record, ref_suffix) from common CloudTrail export / lookup shapes."""
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, dict):
                if "CloudTrailEvent" in item and isinstance(item["CloudTrailEvent"], str):
                    try:
                        inner = json.loads(item["CloudTrailEvent"])
                    except json.JSONDecodeError:
                        continue
                    if isinstance(inner, dict):
                        yield inner, f"{source.name}#lookup-{i}"
                elif item.get("eventName") or item.get("EventName"):
                    yield item, f"{source.name}#list-{i}"
        return
    if isinstance(obj, dict):
        if "Records" in obj and isinstance(obj["Records"], list):
            for i, r in enumerate(obj["Records"]):
                if isinstance(r, dict):
                    yield r, f"{source.name}#rec-{i}"
            return
        if "Events" in obj and isinstance(obj["Events"], list):
            for i, e in enumerate(obj["Events"]):
                if isinstance(e, dict) and isinstance(e.get("CloudTrailEvent"), str):
                    try:
                        inner = json.loads(e["CloudTrailEvent"])
                    except json.JSONDecodeError:
                        continue
                    if isinstance(inner, dict):
                        yield inner, f"{source.name}#evt-{i}"
            return
        if obj.get("eventName") or obj.get("EventName"):
            yield obj, f"{source.name}#root"


def _optional_path(raw_base: Path, p: Path | str | None) -> Path | None:
    if p is None:
        return None
    path = Path(p).expanduser()
    return path.resolve() if path.is_absolute() else (raw_base / path).resolve()


def _declared_from_row(row: dict[str, Any], path: Path) -> DeclaredInventoryRecord:
    inv_id = str(row.get("inventory_id") or row.get("asset_id") or "").strip()
    if not inv_id:
        raise ValueError(f"declared_inventory row missing inventory_id and asset_id in {path}")
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


def _load_csv(path: Path) -> list[dict[str, Any]]:
    return load_csv_rows(path)


class AwsEvidenceProvider:
    """Loads evidence from a directory produced by ``collect_aws_evidence`` (same schema as fixtures)."""

    name = "aws"

    def __init__(self, evidence_root: Path) -> None:
        self.evidence_root = evidence_root.resolve()

    def load(self) -> EvidenceBundle:
        bundle = load_evidence_bundle_from_directory(self.evidence_root)
        validate_evidence_bundle_minimum(bundle)
        return bundle


def collect_ec2_discovered_assets(region: str | None, output_dir: Path) -> Path:
    """Describe EC2 instances and write ``discovered_assets.json`` (fixture-compatible)."""
    region_name = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region_name:
        raise ValueError("AWS region required (argument or AWS_REGION / AWS_DEFAULT_REGION).")

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "discovered_assets.json"

    try:
        ec2 = boto3.client("ec2", region_name=region_name)
        assets: list[dict] = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    asset_id = (
                        tags.get("AssetId")
                        or tags.get("asset_id")
                        or tags.get("Name")
                        or inst.get("InstanceId", "unknown")
                    )
                    assets.append(
                        {
                            "asset_id": asset_id,
                            "provider": "aws",
                            "resource_type": "EC2",
                            "resource_id": inst.get("InstanceId", ""),
                            "account": str(inst.get("OwnerId", "")),
                            "region": region_name,
                            "criticality": tags.get("Criticality", "medium"),
                            "state": str(inst.get("State", {}).get("Name", "")),
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"AWS EC2 describe_instances failed: {e}") from e

    payload = {"assets": assets, "collection": {"region": region_name, "source": "ec2.describe_instances"}}
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def write_evidence_templates(output_dir: Path) -> None:
    """Write minimal companion templates so operators can fill AWS-specific evidence."""
    output_dir.mkdir(parents=True, exist_ok=True)
    templates = {
        "cloud_events.json": [],
        "scanner_findings.json": {"findings": []},
        "scanner_targets.csv": "asset_id,scanner,notes\n",
        "central_log_sources.json": {"sources": []},
        "alert_rules.json": {"rules": []},
        "tickets.json": {"tickets": []},
        "declared_inventory.csv": "asset_id,environment,owner,boundary\n",
        "poam.csv": "weakness,controls,severity,milestones,owner,scheduled_completion\n",
    }
    for name, content in templates.items():
        path = output_dir / name
        if path.exists():
            continue
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_text(json.dumps(content, indent=2), encoding="utf-8")


class AWSProvider(CloudProviderAdapter):
    """
    Normalize previously collected raw AWS JSON (``raw/aws/{account}/{region}/``) into an :class:`AssessmentBundle`.

    Optional companion files (scanner, tickets, POA&M, declared inventory) are loaded from explicit paths when given.
    """

    def __init__(
        self,
        raw_evidence_dir: Path | str,
        *,
        declared_inventory_path: Path | str | None = None,
        scanner_targets_path: Path | str | None = None,
        scanner_findings_path: Path | str | None = None,
        tickets_path: Path | str | None = None,
        poam_path: Path | str | None = None,
    ) -> None:
        self.raw_evidence_dir = Path(raw_evidence_dir).expanduser().resolve()
        base = self.raw_evidence_dir
        self._declared_inventory_path = _optional_path(base, declared_inventory_path)
        self._scanner_targets_path = _optional_path(base, scanner_targets_path)
        self._scanner_findings_path = _optional_path(base, scanner_findings_path)
        self._tickets_path = _optional_path(base, tickets_path)
        self._poam_path = _optional_path(base, poam_path)
        self._bundle: AssessmentBundle | None = None

    def provider_name(self) -> str:
        return "aws"

    def load_bundle(self) -> AssessmentBundle:
        if self._bundle is None:
            self._bundle = self._build_bundle()
        return self._bundle

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

    def _default_timestamp(self, roots: list[Path]) -> datetime:
        for root in roots:
            mf = _read_json(root / "manifest.json")
            if isinstance(mf, dict) and mf.get("collected_at"):
                ts = parse_iso_datetime(str(mf["collected_at"]))
                if ts:
                    return ts
        return datetime.now(timezone.utc)

    def _build_bundle(self) -> AssessmentBundle:
        roots = _discover_region_roots(self.raw_evidence_dir)
        if not roots:
            raise FileNotFoundError(
                f"No AWS raw evidence found under {self.raw_evidence_dir} "
                f"(expected raw/aws/{{account}}/{{region}}/ or a region folder with identity/sts_get_caller_identity.json)."
            )

        default_ts = self._default_timestamp(roots)
        assets_map: dict[tuple[str, str], Asset] = {}
        events: list[SecurityEvent] = []
        log_sources: list[LogSource] = []
        alert_rules: list[AlertRule] = []
        ev_idx = 0

        def add_asset(a: Asset) -> None:
            key = (a.asset_id, a.provider)
            if key not in assets_map:
                assets_map[key] = a

        for root in roots:
            ident = _read_json(root / "identity" / "sts_get_caller_identity.json") or {}
            account = str(ident.get("Account") or root.parent.name or "")
            region = root.name

            # --- Assets: EC2 ---
            inst_data = _read_json(root / "compute" / "ec2_describe_instances.json")
            for page in _iter_ec2_pages(inst_data):
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if not isinstance(inst, dict):
                            continue
                        tags = _tags_to_dict(inst.get("Tags"))
                        iid = str(inst.get("InstanceId") or "unknown")
                        add_asset(
                            Asset(
                                asset_id=_asset_id_from_tags(tags, iid),
                                provider="aws",
                                account_id=account or None,
                                region=region,
                                asset_type="compute",
                                name=str(tags.get("Name") or iid),
                                private_ips=[str(inst["PrivateIpAddress"])] if inst.get("PrivateIpAddress") else [],
                                public_ips=[str(inst["PublicIpAddress"])] if inst.get("PublicIpAddress") else [],
                                tags=tags,
                                criticality=_norm_criticality(tags.get("Criticality")),  # type: ignore[arg-type]
                                environment=_norm_environment(tags),  # type: ignore[arg-type]
                                raw_ref=iid,
                            )
                        )

            # --- Assets: RDS ---
            rds = _read_json(root / "storage" / "rds_describe_db_instances.json")
            if isinstance(rds, dict):
                for db in rds.get("DBInstances", []):
                    if not isinstance(db, dict):
                        continue
                    dbi = str(db.get("DBInstanceIdentifier") or "unknown")
                    tags = _tags_to_dict(db.get("TagList"))
                    add_asset(
                        Asset(
                            asset_id=_asset_id_from_tags(tags, dbi),
                            provider="aws",
                            account_id=account or None,
                            region=region,
                            asset_type="database",
                            name=dbi,
                            private_ips=[],
                            public_ips=[],
                            tags=tags,
                            criticality=_norm_criticality(tags.get("Criticality")),  # type: ignore[arg-type]
                            environment=_norm_environment(tags),  # type: ignore[arg-type]
                            raw_ref=str(db.get("DBInstanceArn") or dbi),
                        )
                    )

            # --- Assets: ELBv2 ---
            lbs = _read_json(root / "load_balancers" / "elbv2_describe_load_balancers.json")
            if isinstance(lbs, dict):
                for lb in lbs.get("LoadBalancers", []):
                    if not isinstance(lb, dict):
                        continue
                    arn = str(lb.get("LoadBalancerArn") or "")
                    name = str(lb.get("LoadBalancerName") or arn.split("/")[-1] if arn else "lb")
                    add_asset(
                        Asset(
                            asset_id=name,
                            provider="aws",
                            account_id=account or None,
                            region=region,
                            asset_type="load_balancer",
                            name=name,
                            private_ips=[],
                            public_ips=[],
                            tags={},
                            criticality="moderate",
                            environment="unknown",  # type: ignore[arg-type]
                            raw_ref=arn or name,
                        )
                    )

            # --- Assets: S3 ---
            s3b = _read_json(root / "storage" / "s3_list_buckets.json")
            if isinstance(s3b, dict):
                for b in s3b.get("Buckets", []):
                    if not isinstance(b, dict):
                        continue
                    name = str(b.get("Name") or "").strip()
                    if not name:
                        continue
                    add_asset(
                        Asset(
                            asset_id=name,
                            provider="aws",
                            account_id=account or None,
                            region=region,
                            asset_type="storage",
                            name=name,
                            private_ips=[],
                            public_ips=[],
                            tags={},
                            criticality="moderate",
                            environment="unknown",  # type: ignore[arg-type]
                            raw_ref=f"arn:aws:s3:::{name}",
                        )
                    )

            # --- Assets: EBS volumes ---
            vol_data = _read_json(root / "compute" / "ec2_describe_volumes.json")
            for page in _iter_ec2_pages(vol_data):
                for vol in page.get("Volumes", []):
                    if not isinstance(vol, dict):
                        continue
                    vid = str(vol.get("VolumeId") or "")
                    if not vid:
                        continue
                    add_asset(
                        Asset(
                            asset_id=vid,
                            provider="aws",
                            account_id=account or None,
                            region=region,
                            asset_type="storage",
                            name=vid,
                            private_ips=[],
                            public_ips=[],
                            tags=_tags_to_dict(vol.get("Tags")),
                            criticality="moderate",
                            environment="unknown",  # type: ignore[arg-type]
                            raw_ref=vid,
                        )
                    )

            # --- Security groups -> synthetic events ---
            sg_data = _read_json(root / "compute" / "ec2_describe_security_groups.json")
            for page in _iter_ec2_pages(sg_data):
                for sg in page.get("SecurityGroups", []):
                    if not isinstance(sg, dict):
                        continue
                    for row in extract_security_group_exposures(sg):
                        ev_idx += 1
                        st = coerce_semantic_type(str(row["semantic_type"]))
                        events.append(
                            SecurityEvent(
                                event_id=f"sg-{row['group_id']}-{row['port']}-{ev_idx}",
                                provider="aws",
                                semantic_type=st,
                                timestamp=default_ts,
                                actor=None,
                                asset_id=None,
                                resource_id=str(row.get("group_id") or ""),
                                port=int(row["port"]),
                                protocol=str(row.get("protocol") or "tcp"),
                                raw_event_name="DescribeSecurityGroupInference",
                                raw_ref=f"{root}/compute/ec2_describe_security_groups.json#sg-{row['group_id']}-{row['port']}",
                                metadata={"cidr": row.get("cidr"), "vpc_id": row.get("vpc_id"), "inferred": True},
                            )
                        )

            # --- CloudTrail-like JSON under this region tree ---
            for path in sorted(root.rglob("*.json")):
                rel = str(path.relative_to(root))
                if rel == "manifest.json" or "/manifest.json" in rel:
                    continue
                if path.name in (
                    "sts_get_caller_identity.json",
                    "iam_get_account_summary.json",
                    "iam_get_account_password_policy.json",
                    "iam_get_credential_report.json",
                    "iam_list_users.json",
                    "iam_list_roles.json",
                    "iam_list_policies_local.json",
                    "iam_list_virtual_mfa_devices.json",
                ):
                    continue
                if path.parent.name in ("identity",) and "sts_" not in path.name:
                    continue
                data = _read_json(path)
                if data is None:
                    continue
                for rec, suf in _iter_cloudtrail_like_records(data, path):
                    en = str(rec.get("eventName") or rec.get("EventName") or "")
                    if not en:
                        continue
                    st_raw, meta = semantic_type_from_cloudtrail_event(rec)
                    st = coerce_semantic_type(st_raw)
                    ts = extract_event_time(rec) or default_ts
                    ev_idx += 1
                    events.append(
                        SecurityEvent(
                            event_id=f"ct-{ev_idx}-{re.sub(r'[^a-zA-Z0-9_-]+', '-', en)}"[:120],
                            provider="aws",
                            semantic_type=st,
                            timestamp=ts,
                            actor=extract_actor_from_cloudtrail(rec),
                            asset_id=None,
                            resource_id=_resource_from_ct(rec),
                            port=None,
                            raw_event_name=en,
                            raw_ref=f"{path}#{suf}",
                            metadata=meta,
                        )
                    )

            # --- Log sources: CloudTrail + VPC flow logs (no Splunk/Sentinel unless present in raw) ---
            trails = _read_json(root / "logging" / "cloudtrail_describe_trails.json")
            statuses = _read_json(root / "logging" / "cloudtrail_get_trail_status_by_trail.json") or {}
            if isinstance(trails, dict):
                idx = 0
                for trail in trails.get("trailList", []):
                    if not isinstance(trail, dict):
                        continue
                    name = str(trail.get("Name") or "")
                    home = trail.get("HomeRegion")
                    if home and str(home) != region and not trail.get("IsMultiRegionTrail"):
                        continue
                    suf = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(trail.get("TrailARN") or name))[:120]
                    st_obj = statuses.get(suf) if isinstance(statuses, dict) else None
                    is_logging = bool(st_obj.get("IsLogging")) if isinstance(st_obj, dict) else True
                    cw_arn = trail.get("CloudWatchLogsLogGroupArn")
                    central: CentralDestination | None = "cloudwatch" if cw_arn else None
                    log_sources.append(
                        LogSource(
                            log_source_id=f"trail-{name or idx}-{region}",
                            asset_id=None,
                            source_type="cloud_control_plane",
                            local_source=str(trail.get("S3BucketName") or trail.get("TrailARN") or name),
                            central_destination=central,
                            last_seen=default_ts if is_logging else None,
                            status="active" if is_logging else "stale",
                            sample_local_event_ref=None,
                            sample_central_event_ref=str(cw_arn) if cw_arn else None,
                        )
                    )
                    idx += 1

            flow_data = _read_json(root / "compute" / "ec2_describe_flow_logs.json")
            for page in _iter_ec2_pages(flow_data):
                for fl in page.get("FlowLogs", []):
                    if not isinstance(fl, dict):
                        continue
                    fid = str(fl.get("FlowLogId") or "")
                    rid = str(fl.get("ResourceId") or "")
                    log_sources.append(
                        LogSource(
                            log_source_id=f"flow-{fid}-{region}",
                            asset_id=rid if rid else None,
                            source_type="network_flow",
                            local_source=fid,
                            central_destination=None,
                            last_seen=default_ts,
                            status="active",
                        )
                    )

            # CloudWatch log groups (if operator added a dump)
            for extra in ("logging/describe_log_groups.json", "logging/cloudwatch_describe_log_groups.json"):
                lg = _read_json(root / extra)
                if isinstance(lg, dict) and isinstance(lg.get("logGroups"), list):
                    for i, g in enumerate(lg["logGroups"]):
                        if not isinstance(g, dict):
                            continue
                        arn = str(g.get("arn") or g.get("logGroupName") or f"lg-{i}")
                        log_sources.append(
                            LogSource(
                                log_source_id=f"cwlg-{i}-{region}",
                                asset_id=None,
                                source_type="app_audit",
                                local_source=str(g.get("logGroupName") or arn),
                                central_destination="cloudwatch",
                                last_seen=default_ts,
                                status="active",
                                sample_central_event_ref=arn,
                            )
                        )

            # --- Alert rules: CloudWatch alarms ---
            alarms = _read_json(root / "logging" / "cloudwatch_describe_alarms_pages.json")
            if isinstance(alarms, dict):
                for pi, page in enumerate(alarms.get("Pages") or []):
                    if not isinstance(page, dict):
                        continue
                    for ai, a in enumerate(page.get("MetricAlarms", [])):
                        if not isinstance(a, dict):
                            continue
                        aname = str(a.get("AlarmName") or f"alarm-{pi}-{ai}")
                        alert_rules.append(
                            AlertRule(
                                rule_id=f"cw-{region}-{re.sub(r'[^a-zA-Z0-9_-]+', '-', aname)}"[:120],
                                platform="aws_cloudwatch",
                                name=aname,
                                enabled=str(a.get("StateValue", "")).upper() in ("OK", "ALARM"),
                                mapped_semantic_types=[],
                                recipients=[],
                                controls=["SI-4", "AU-6"],
                                last_fired=None,
                                sample_alert_ref=f"arn:aws:cloudwatch:{region}:{account}:alarm:{aname}",
                            )
                        )

            # --- GuardDuty enabled detectors ---
            gd = _read_json(root / "logging" / "guardduty_detectors_and_findings.json")
            if isinstance(gd, dict):
                for i, det in enumerate(gd.get("detectors", [])):
                    if not isinstance(det, dict):
                        continue
                    did = str(det.get("detector_id") or f"d{i}")
                    info = det.get("detector") or {}
                    status = str(info.get("Status", "")).lower() if isinstance(info, dict) else ""
                    if status != "enabled":
                        continue
                    alert_rules.append(
                        AlertRule(
                            rule_id=f"gd-{did}-{region}",
                            platform="aws_guardduty",
                            name=f"GuardDuty detector {did}",
                            enabled=True,
                            mapped_semantic_types=["unknown"],
                            recipients=[],
                            controls=["SI-4", "RA-5"],
                            sample_alert_ref=f"guardduty:{region}:{did}",
                        )
                    )

            # --- AWS Config rules ---
            cfg = _read_json(root / "logging" / "configservice_describe_config_rules.json")
            if isinstance(cfg, dict):
                for i, rule in enumerate(cfg.get("ConfigRules", [])):
                    if not isinstance(rule, dict):
                        continue
                    rid = str(rule.get("ConfigRuleName") or f"cfg-{i}")
                    alert_rules.append(
                        AlertRule(
                            rule_id=f"cfg-{rid}-{region}"[:120],
                            platform="aws_config",
                            name=rid,
                            enabled=str(rule.get("ConfigRuleState", "")).upper() == "ACTIVE",
                            mapped_semantic_types=["unknown"],
                            recipients=[],
                            controls=["CM-6", "SI-4"],
                            sample_alert_ref=f"config:{region}:{rid}",
                        )
                    )

        declared: list[DeclaredInventoryRecord] = []
        inv_p = self._declared_inventory_path
        if inv_p and inv_p.is_file():
            for row in _load_csv(inv_p):
                declared.append(_declared_from_row(row, inv_p))

        targets: list[ScannerTarget] = []
        st_path = self._scanner_targets_path
        if st_path and st_path.is_file():
            for row in _load_csv(st_path):
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

        findings: list[ScannerFinding] = []
        sf_path = self._scanner_findings_path
        if sf_path and sf_path.is_file():
            raw_f = _read_json(sf_path) or {}
            items = raw_f.get("findings", raw_f) if isinstance(raw_f, dict) else []
            if not isinstance(items, list):
                items = []
            default_scanner = str(raw_f.get("scanner", "nessus")) if isinstance(raw_f, dict) else "nessus"
            for row in items:
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
                    )
                )

        tickets_out: list[Ticket] = []
        tx_path = self._tickets_path
        if tx_path and tx_path.is_file():
            tdata = _read_json(tx_path) or {}
            tix = tdata.get("tickets", tdata) if isinstance(tdata, dict) else []
            if not isinstance(tix, list):
                tix = []
            system_default: TicketSystem = "jira"
            sys_raw = tdata.get("system") if isinstance(tdata, dict) else None
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

        poam_items: list[PoamItem] = []
        poam_p = self._poam_path
        if poam_p and poam_p.is_file():
            for row in _load_csv(poam_p):
                if not row:
                    continue
                ctrl_raw = row.get("controls") or ""
                controls = [c.strip() for c in str(ctrl_raw).replace(";", ",").split(",") if c.strip()]
                wn = str(row.get("weakness_name") or "weakness")
                notes = str(row.get("notes") or row.get("weakness_description") or wn)
                raw_sev = str(row.get("raw_severity") or "moderate").lower()
                adj = str(row.get("adjusted_risk_rating") or raw_sev)
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

        try:
            return AssessmentBundle(
                assets=list(assets_map.values()),
                declared_inventory=declared,
                events=events,
                scanner_targets=targets,
                scanner_findings=findings,
                log_sources=log_sources,
                alert_rules=alert_rules,
                tickets=tickets_out,
                poam_items=poam_items,
            )
        except ValidationError as e:
            raise ValueError(f"AWS raw evidence produced invalid canonical bundle: {e}") from e
