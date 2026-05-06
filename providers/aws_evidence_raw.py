"""AWS raw evidence collection: JSON-safe helpers and boto3 orchestration (used by ``collect_aws_evidence`` only)."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------------------
# JSON serialization (tested)
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Recursively convert boto3/botocore objects into JSON-serializable values."""
    if obj is None or isinstance(obj, (bool, str, int)):
        return obj
    if isinstance(obj, float):
        return obj if obj == obj and abs(obj) != float("inf") else str(obj)  # NaN/inf
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, set):
        return sorted(to_jsonable(x) for x in obj)  # type: ignore[arg-type]
    return str(obj)


def write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(data), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Manifest / call recording
# ---------------------------------------------------------------------------


@dataclass
class CallFailure:
    call: str
    error_code: str
    message: str


@dataclass
class CollectionManifest:
    collected_at: str
    account_id: str
    region: str
    account_label: str | None
    successful_calls: list[str] = field(default_factory=list)
    failed_calls: list[CallFailure] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        denied = [f for f in self.failed_calls if "denied" in f.error_code.lower() or "unauthorized" in f.error_code.lower()]
        return {
            "collected_at": self.collected_at,
            "account_id": self.account_id,
            "region": self.region,
            "account_label": self.account_label,
            "successful_calls": list(self.successful_calls),
            "failed_calls": [
                {"call": f.call, "error_code": f.error_code, "message": f.message} for f in self.failed_calls
            ],
            "errors": [f"{f.call}: [{f.error_code}] {f.message}" for f in self.failed_calls],
            "permission_coverage": {
                "successful_call_count": len(self.successful_calls),
                "failed_call_count": len(self.failed_calls),
                "access_denied_call_count": len(denied),
                "assessment_confidence": "partial" if self.failed_calls else "complete",
                "impact": [
                    {
                        "call": f.call,
                        "error_code": f.error_code,
                        "assessment_impact": _assessment_impact_for_call(f.call),
                    }
                    for f in self.failed_calls
                ],
            },
        }


def _assessment_impact_for_call(call_id: str) -> str:
    c = call_id.lower()
    if c.startswith("iam:"):
        return "Identity and MFA evidence may be incomplete."
    if c.startswith("ec2:"):
        return "Inventory, exposure, scanner-scope, or network-log evidence may be incomplete."
    if c.startswith("cloudtrail:"):
        return "Cloud control-plane event and audit-log evidence may be incomplete."
    if c.startswith("guardduty:"):
        return "Threat detection evidence may be incomplete."
    if c.startswith("config:") or c.startswith("cloudwatch:"):
        return "Configuration-rule or alert instrumentation evidence may be incomplete."
    if c.startswith("s3:") or c.startswith("rds:") or c.startswith("elbv2:"):
        return "Storage, database, or load-balancer inventory evidence may be incomplete."
    return "Collected evidence is partial for this API call."


def safe_client_call(
    manifest: CollectionManifest,
    call_id: str,
    fn: Callable[[], Any],
) -> Any | None:
    """Invoke a zero-arg callable; record success or ClientError/BotoCoreError; never raises."""
    try:
        out = fn()
        manifest.successful_calls.append(call_id)
        return out
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "ClientError")
        msg = (e.response.get("Error") or {}).get("Message", str(e))
        manifest.failed_calls.append(CallFailure(call=call_id, error_code=code, message=msg))
        return None
    except BotoCoreError as e:
        manifest.failed_calls.append(CallFailure(call=call_id, error_code="BotoCoreError", message=str(e)))
        return None
    except Exception as e:  # noqa: BLE001 — surface unexpected bugs without aborting full run
        manifest.failed_calls.append(
            CallFailure(call=call_id, error_code=type(e).__name__, message=str(e))
        )
        return None


# ---------------------------------------------------------------------------
# Fixture-compatible synthesis (tested pieces)
# ---------------------------------------------------------------------------


def _tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    if not tags:
        return {}
    return {t["Key"]: t["Value"] for t in tags if "Key" in t and "Value" in t}


def _asset_id_from_tags(tags: dict[str, str], fallback: str) -> str:
    return (
        tags.get("AssetId")
        or tags.get("asset_id")
        or tags.get("Name")
        or fallback
    )


def build_discovered_assets_payload(
    *,
    account_id: str,
    region: str,
    as_of: str,
    describe_instances_pages: list[dict[str, Any]],
    describe_db_instances_response: dict[str, Any] | None,
    describe_load_balancers_response: dict[str, Any] | None,
    list_buckets_response: dict[str, Any] | None,
) -> dict[str, Any]:
    """Shape `discovered_assets.json` like fixtures from raw API payloads."""
    assets: list[dict[str, Any]] = []

    for page in describe_instances_pages:
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                tags = _tags_to_dict(inst.get("Tags"))
                iid = inst.get("InstanceId") or "unknown"
                assets.append(
                    {
                        "asset_id": _asset_id_from_tags(tags, iid),
                        "provider": "aws",
                        "resource_type": "EC2",
                        "resource_id": iid,
                        "account": str(inst.get("OwnerId") or account_id),
                        "region": region,
                        "criticality": tags.get("Criticality", tags.get("criticality", "medium")),
                        "name": tags.get("Name", iid),
                        "private_ip": (inst.get("PrivateIpAddress") or ""),
                        "public_ip": (inst.get("PublicIpAddress") or ""),
                        "vpc_id": inst.get("VpcId") or "",
                        "security_groups": [g.get("GroupId") for g in inst.get("SecurityGroups", []) if g.get("GroupId")],
                        "tags": tags,
                        "state": str((inst.get("State") or {}).get("Name", "")),
                    }
                )

    if describe_db_instances_response:
        for db in describe_db_instances_response.get("DBInstances", []):
            dbi = db.get("DBInstanceIdentifier") or "unknown"
            arn = db.get("DBInstanceArn") or ""
            tags = _tags_to_dict(db.get("TagList"))
            assets.append(
                {
                    "asset_id": _asset_id_from_tags(tags, dbi),
                    "provider": "aws",
                    "resource_type": "RDS",
                    "resource_id": arn or dbi,
                    "account": account_id,
                    "region": region,
                    "criticality": tags.get("Criticality", "medium"),
                    "name": dbi,
                    "private_ip": (db.get("Endpoint") or {}).get("Address", "") if isinstance(db.get("Endpoint"), dict) else "",
                    "public_ip": "",
                    "tags": tags,
                }
            )

    if describe_load_balancers_response:
        for lb in describe_load_balancers_response.get("LoadBalancers", []):
            arn = lb.get("LoadBalancerArn") or ""
            name = lb.get("LoadBalancerName") or arn.split("/")[-1] if arn else "unknown"
            tags_resp = lb.get("Tags")  # usually not embedded; may be empty
            tags: dict[str, str] = {}
            if isinstance(tags_resp, list):
                tags = _tags_to_dict(tags_resp)
            assets.append(
                {
                    "asset_id": _asset_id_from_tags(tags, name),
                    "provider": "aws",
                    "resource_type": "ELB",
                    "resource_id": arn,
                    "account": account_id,
                    "region": region,
                    "criticality": tags.get("Criticality", "medium"),
                    "name": name,
                    "scheme": lb.get("Scheme", ""),
                    "vpc_id": lb.get("VpcId", ""),
                    "tags": tags,
                }
            )

    if list_buckets_response:
        for b in list_buckets_response.get("Buckets", []):
            name = b.get("Name")
            if not name:
                continue
            assets.append(
                {
                    "asset_id": name,
                    "provider": "aws",
                    "resource_type": "S3",
                    "resource_id": f"arn:aws:s3:::{name}",
                    "account": account_id,
                    "region": region,
                    "criticality": "medium",
                    "name": name,
                    "tags": {},
                }
            )

    return {
        "collection": {
            "source": "aws_collect",
            "account": account_id,
            "region": region,
            "as_of": as_of,
        },
        "assets": assets,
    }


def build_central_log_sources_payload(
    *,
    account_id: str,
    region: str,
    describe_trails_response: dict[str, Any] | None,
    describe_flow_logs_pages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Infer central_log_sources.json-style hints from CloudTrail + VPC flow logs."""
    sources: list[dict[str, Any]] = []
    seen = 0
    if describe_trails_response:
        for trail in describe_trails_response.get("trailList", []):
            home = trail.get("HomeRegion")
            is_multi = trail.get("IsMultiRegionTrail")
            if home and home != region and not is_multi:
                continue
            name = trail.get("Name") or trail.get("TrailARN", "").split("/")[-1]
            if not name:
                continue
            cw = trail.get("CloudWatchLogsLogGroupArn")
            s3 = trail.get("S3BucketName")
            local_parts = []
            if s3:
                local_parts.append(f"S3 bucket {s3}")
            if cw:
                local_parts.append("CloudWatch Logs delivery")
            dest = "cloudwatch_logs" if cw else ("s3" if s3 else "unknown")
            sources.append(
                {
                    "name": f"cloudtrail-{name}",
                    "log_source_id": f"ls-cloudtrail-{seen}",
                    "asset_id": "org-wide-aws",
                    "source_type": "cloud_control_plane",
                    "local_source": " / ".join(local_parts) or "CloudTrail",
                    "central_destination": dest,
                    "seen_last_24h": True,
                    "local_only": False,
                    "index": "",
                    "notes": f"Trail ARN {trail.get('TrailARN', '')} (inferred from describe_trails; tune for your SIEM).",
                }
            )
            seen += 1

    for page in describe_flow_logs_pages:
        for fl in page.get("FlowLogs", []):
            fid = fl.get("FlowLogId") or f"fl-{seen}"
            rid = fl.get("ResourceId") or ""
            sources.append(
                {
                    "name": f"vpc-flow-{fid}",
                    "log_source_id": f"ls-flow-{fid}",
                    "asset_id": rid or "vpc-flow",
                    "source_type": "network_flow",
                    "local_source": f"Flow log {fid} ({fl.get('TrafficType', '')})",
                    "central_destination": "unknown",
                    "seen_last_24h": True,
                    "local_only": True,
                    "index": "",
                    "notes": "VPC flow logs present; map central_destination to your log archive/SIEM.",
                }
            )

    return {"siem": "unknown", "sources": sources}


def build_alert_rules_from_cloudwatch(
    describe_alarms_pages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Map CloudWatch alarms to alert_rules.json-style stubs."""
    rules: list[dict[str, Any]] = []
    idx = 0
    for page in describe_alarms_pages:
        for a in page.get("MetricAlarms", []):
            aid = a.get("AlarmName") or f"alarm-{idx}"
            rules.append(
                {
                    "rule_id": f"cw-{idx}",
                    "name": aid,
                    "enabled": str(a.get("StateValue", "")).upper() in ("OK", "ALARM"),
                    "event_types": [],
                    "matches_event_type": None,
                    "mapped_semantic_types": [],
                    "recipients": [],
                    "controls": ["SI-4", "AU-6"],
                    "last_fired": None,
                    "sample_alert_ref": f"cloudwatch://alarm/{aid}",
                    "alarm_state": a.get("StateValue"),
                    "metric_name": a.get("MetricName"),
                }
            )
            idx += 1
    return {"platform": "cloudwatch", "rules": rules}


def _guardduty_resource_id(res: Mapping[str, Any], fid: str) -> str:
    if res.get("InstanceId"):
        return str(res["InstanceId"])
    s3d = res.get("S3BucketDetails")
    if isinstance(s3d, list) and s3d:
        first = s3d[0]
        if isinstance(first, dict):
            return str(first.get("Arn") or first.get("BucketArn") or first.get("Name") or fid)
    return str(fid)


def guardduty_finding_to_semantic_event(
    finding: Mapping[str, Any],
    *,
    region: str,
    account_id: str,
) -> dict[str, Any]:
    """Convert one GuardDuty finding into a semantic-style cloud_events row (no secrets)."""
    fid = finding.get("Id") or finding.get("Arn", "") or "unknown"
    sev = str(finding.get("Severity", ""))
    etype = str(finding.get("Type", "GuardDuty.Finding"))
    res = finding.get("Resource") or {}
    details = finding.get("Service", {}) or {}
    rid = _guardduty_resource_id(res, fid)
    return {
        "event_type": "guardduty.threat_detected",
        "provider": "aws",
        "actor": "guardduty",
        "asset_id": str(res.get("InstanceId") or "org-wide-aws"),
        "resource_id": rid,
        "timestamp": finding.get("UpdatedAt") or finding.get("CreatedAt") or "",
        "raw_event_ref": f"guardduty:{region}:{fid}",
        "metadata": {
            "severity": sev,
            "finding_type": etype,
            "count": details.get("Count"),
            "archived": finding.get("Archived"),
            "account_id": account_id,
            "region": region,
        },
    }


def _trail_file_suffix(arn_or_name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", arn_or_name)
    return safe[:200]


def paginate_all(
    paginator_name: str,
    client: Any,
    manifest: CollectionManifest,
    call_prefix: str,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Run boto3 paginator and collect all pages; record failures on paginator creation or page iteration."""
    call_id = f"{call_prefix}:{paginator_name}"
    try:
        paginator = client.get_paginator(paginator_name)
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "ClientError")
        msg = (e.response.get("Error") or {}).get("Message", str(e))
        manifest.failed_calls.append(CallFailure(call=call_id, error_code=code, message=msg))
        return []
    except BotoCoreError as e:
        manifest.failed_calls.append(CallFailure(call=call_id, error_code="BotoCoreError", message=str(e)))
        return []

    pages: list[dict[str, Any]] = []
    try:
        for page in paginator.paginate(**kwargs):
            pages.append(page)
        manifest.successful_calls.append(call_id)
        return pages
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "ClientError")
        msg = (e.response.get("Error") or {}).get("Message", str(e))
        manifest.failed_calls.append(CallFailure(call=call_id, error_code=code, message=msg))
        return pages
    except BotoCoreError as e:
        manifest.failed_calls.append(CallFailure(call=call_id, error_code="BotoCoreError", message=str(e)))
        return pages


def collect_aws_raw_evidence(
    session: Any,
    *,
    region: str,
    output_dir: Path,
    account_label: str | None,
    fixture_compatible: bool,
    collected_at_iso: str,
) -> Path:
    """
    Write raw JSON under ``output_dir / 'raw' / 'aws' / {account_id} / {region} /`` and return manifest path.

    Does not raise on partial AccessDenied; records failures in manifest.
    """
    output_dir = output_dir.resolve()
    sts = session.client("sts", region_name=region)
    manifest = CollectionManifest(
        collected_at=collected_at_iso,
        account_id="unknown",
        region=region,
        account_label=account_label,
    )

    ident = safe_client_call(manifest, "sts:GetCallerIdentity", lambda: sts.get_caller_identity())
    if isinstance(ident, dict) and ident.get("Account"):
        manifest.account_id = str(ident["Account"])

    account_id = manifest.account_id
    dest = output_dir / "raw" / "aws" / account_id / region
    identity_dir = dest / "identity"
    compute_dir = dest / "compute"
    lb_dir = dest / "load_balancers"
    storage_dir = dest / "storage"
    logging_dir = dest / "logging"

    if ident is not None:
        write_json_file(identity_dir / "sts_get_caller_identity.json", ident)

    iam = session.client("iam", region_name=region)

    def _iam(name: str, fn: Callable[[], Any]) -> Any | None:
        return safe_client_call(manifest, name, fn)

    summary = _iam("iam:GetAccountSummary", lambda: iam.get_account_summary())
    if summary is not None:
        write_json_file(identity_dir / "iam_get_account_summary.json", summary)

    def _password_policy() -> dict[str, Any]:
        try:
            return iam.get_account_password_policy()
        except ClientError as e:
            code = (e.response.get("Error") or {}).get("Code", "")
            if code in ("NoSuchEntityException", "NoSuchEntity"):
                return {"NoSuchEntityException": True, "note": "No account password policy configured."}
            raise

    pp = _iam("iam:GetAccountPasswordPolicy", _password_policy)
    if pp is not None:
        write_json_file(identity_dir / "iam_get_account_password_policy.json", pp)

    def _credential_report() -> dict[str, Any]:
        iam.generate_credential_report()
        for _ in range(15):
            try:
                r = iam.get_credential_report()
                content = r.get("Content")
                if isinstance(content, bytes):
                    csv_text = content.decode("utf-8", errors="replace")
                else:
                    csv_text = str(content or "")
                return {"GeneratedTime": r.get("GeneratedTime"), "credential_report_csv": csv_text}
            except ClientError as e:
                if (e.response.get("Error") or {}).get("Code") == "CredentialReportNotPresent":
                    time.sleep(1.0)
                    continue
                if (e.response.get("Error") or {}).get("Code") == "ReportInProgress":
                    time.sleep(0.6)
                    continue
                raise
        return {"error": "timeout waiting for credential report"}

    cr = _iam("iam:GetCredentialReport", _credential_report)
    if cr is not None:
        write_json_file(identity_dir / "iam_get_credential_report.json", cr)

    users_pages = paginate_all("list_users", iam, manifest, "iam")
    if users_pages:
        merged_users = {"Users": [], "IsTruncated": False}
        for p in users_pages:
            merged_users["Users"].extend(p.get("Users", []))
        write_json_file(identity_dir / "iam_list_users.json", merged_users)

    roles_pages = paginate_all("list_roles", iam, manifest, "iam")
    if roles_pages:
        merged = {"Roles": []}
        for p in roles_pages:
            merged["Roles"].extend(p.get("Roles", []))
        write_json_file(identity_dir / "iam_list_roles.json", merged)

    lp_pages = paginate_all("list_policies", iam, manifest, "iam", Scope="Local")
    if lp_pages:
        merged_p = {"Policies": []}
        for p in lp_pages:
            merged_p["Policies"].extend(p.get("Policies", []))
        write_json_file(identity_dir / "iam_list_policies_local.json", merged_p)

    vmfa = _iam("iam:ListVirtualMFADevices", lambda: iam.list_virtual_mfa_devices())
    if vmfa is not None:
        write_json_file(identity_dir / "iam_list_virtual_mfa_devices.json", vmfa)

    ec2 = session.client("ec2", region_name=region)

    def _ec2_paginator(name: str, json_name: str) -> list[dict[str, Any]]:
        pages = paginate_all(name, ec2, manifest, "ec2")
        if pages:
            write_json_file(compute_dir / f"ec2_{json_name}.json", {"Pages": pages})
        return pages

    inst_pages = _ec2_paginator("describe_instances", "describe_instances")
    _ec2_paginator("describe_security_groups", "describe_security_groups")
    _ec2_paginator("describe_network_acls", "describe_network_acls")
    _ec2_paginator("describe_route_tables", "describe_route_tables")
    _ec2_paginator("describe_vpc_peering_connections", "describe_vpc_peering_connections")
    _ec2_paginator("describe_vpc_endpoints", "describe_vpc_endpoints")
    flow_pages = _ec2_paginator("describe_flow_logs", "describe_flow_logs")
    _ec2_paginator("describe_volumes", "describe_volumes")

    elbv2 = session.client("elbv2", region_name=region)
    lbs = safe_client_call(manifest, "elbv2:DescribeLoadBalancers", lambda: elbv2.describe_load_balancers())
    listeners_by_arn: dict[str, Any] = {}
    attrs_by_arn: dict[str, Any] = {}
    if isinstance(lbs, dict):
        write_json_file(lb_dir / "elbv2_describe_load_balancers.json", lbs)
        for lb in lbs.get("LoadBalancers", []):
            arn = lb.get("LoadBalancerArn")
            if not arn:
                continue
            lid = f"elbv2:DescribeListeners:{arn}"
            ls = safe_client_call(
                manifest,
                lid,
                lambda a=arn: elbv2.describe_listeners(LoadBalancerArn=a),
            )
            if ls is not None:
                listeners_by_arn[arn] = ls
            aid = f"elbv2:DescribeLoadBalancerAttributes:{arn}"
            at = safe_client_call(
                manifest,
                aid,
                lambda a=arn: elbv2.describe_load_balancer_attributes(LoadBalancerArn=a),
            )
            if at is not None:
                attrs_by_arn[arn] = at
    if listeners_by_arn:
        write_json_file(lb_dir / "elbv2_describe_listeners_by_lb.json", {"by_load_balancer_arn": listeners_by_arn})
    if attrs_by_arn:
        write_json_file(
            lb_dir / "elbv2_describe_load_balancer_attributes_by_lb.json",
            {"by_load_balancer_arn": attrs_by_arn},
        )

    s3 = session.client("s3", region_name=region)
    buckets_resp = safe_client_call(manifest, "s3:ListBuckets", lambda: s3.list_buckets())
    if isinstance(buckets_resp, dict):
        write_json_file(storage_dir / "s3_list_buckets.json", buckets_resp)

    bucket_rows: list[dict[str, Any]] = []
    if isinstance(buckets_resp, dict):
        for b in buckets_resp.get("Buckets", []):
            name = b.get("Name")
            if not name:
                continue
            row: dict[str, Any] = {"Name": name, "CreationDate": b.get("CreationDate")}
            pab = safe_client_call(
                manifest,
                f"s3:GetPublicAccessBlock:{name}",
                lambda n=name: s3.get_public_access_block(Bucket=n),
            )
            if pab is not None:
                row["PublicAccessBlockConfiguration"] = pab.get("PublicAccessBlockConfiguration")
            st = safe_client_call(
                manifest,
                f"s3:GetBucketPolicyStatus:{name}",
                lambda n=name: s3.get_bucket_policy_status(Bucket=n),
            )
            if st is not None:
                row["PolicyStatus"] = st.get("PolicyStatus")
            enc = safe_client_call(
                manifest,
                f"s3:GetBucketEncryption:{name}",
                lambda n=name: s3.get_bucket_encryption(Bucket=n),
            )
            if enc is not None:
                row["ServerSideEncryptionConfiguration"] = enc.get("ServerSideEncryptionConfiguration")
            log = safe_client_call(
                manifest,
                f"s3:GetBucketLogging:{name}",
                lambda n=name: s3.get_bucket_logging(Bucket=n),
            )
            if log is not None:
                row["LoggingEnabled"] = log.get("LoggingEnabled")
            bucket_rows.append(row)
    if bucket_rows:
        write_json_file(storage_dir / "s3_bucket_details.json", {"buckets": bucket_rows})

    rds = session.client("rds", region_name=region)
    dbs = safe_client_call(manifest, "rds:DescribeDBInstances", lambda: rds.describe_db_instances())
    if isinstance(dbs, dict):
        write_json_file(storage_dir / "rds_describe_db_instances.json", dbs)

    snap_payload: dict[str, Any] = {}
    auto = safe_client_call(
        manifest,
        "rds:DescribeDBSnapshots(automated)",
        lambda: rds.describe_db_snapshots(SnapshotType="automated", MaxRecords=50),
    )
    if auto is not None:
        snap_payload["automated"] = auto
    manual = safe_client_call(
        manifest,
        "rds:DescribeDBSnapshots(manual)",
        lambda: rds.describe_db_snapshots(SnapshotType="manual", MaxRecords=50),
    )
    if manual is not None:
        snap_payload["manual"] = manual
    if snap_payload:
        write_json_file(storage_dir / "rds_describe_db_snapshots.json", snap_payload)

    ct = session.client("cloudtrail", region_name=region)
    trails = safe_client_call(manifest, "cloudtrail:DescribeTrails", lambda: ct.describe_trails())
    if isinstance(trails, dict):
        write_json_file(logging_dir / "cloudtrail_describe_trails.json", trails)

    trail_list = trails.get("trailList", []) if isinstance(trails, dict) else []
    statuses: dict[str, Any] = {}
    selectors: dict[str, Any] = {}
    for trail in trail_list:
        home = trail.get("HomeRegion")
        name = trail.get("Name")
        if not name:
            continue
        if home and home != region and not trail.get("IsMultiRegionTrail"):
            continue
        suf = _trail_file_suffix(trail.get("TrailARN", name))
        st = safe_client_call(
            manifest,
            f"cloudtrail:GetTrailStatus:{name}",
            lambda n=name: ct.get_trail_status(Name=n),
        )
        if st is not None:
            statuses[suf] = st
        es = safe_client_call(
            manifest,
            f"cloudtrail:GetEventSelectors:{name}",
            lambda n=name: ct.get_event_selectors(TrailName=n),
        )
        if es is not None:
            selectors[suf] = es
    if statuses:
        write_json_file(logging_dir / "cloudtrail_get_trail_status_by_trail.json", statuses)
    if selectors:
        write_json_file(logging_dir / "cloudtrail_get_event_selectors_by_trail.json", selectors)

    gd = session.client("guardduty", region_name=region)
    det_ids = safe_client_call(manifest, "guardduty:ListDetectors", lambda: gd.list_detectors())
    gd_payload: dict[str, Any] = {"detectors": []}
    if isinstance(det_ids, dict):
        for did in det_ids.get("DetectorIds", []):
            det_entry: dict[str, Any] = {"detector_id": did}
            info = safe_client_call(
                manifest,
                f"guardduty:GetDetector:{did}",
                lambda d=did: gd.get_detector(DetectorId=d),
            )
            if info is not None:
                det_entry["detector"] = info
            fids = safe_client_call(
                manifest,
                f"guardduty:ListFindings:{did}",
                lambda d=did: gd.list_findings(DetectorId=d, MaxResults=50),
            )
            findings_list: list[Any] = []
            if isinstance(fids, dict):
                ids = fids.get("FindingIds", [])
                if ids:
                    gf = safe_client_call(
                        manifest,
                        f"guardduty:GetFindings:{did}",
                        lambda d=did, i=ids: gd.get_findings(DetectorId=d, FindingIds=i[:50]),
                    )
                    if isinstance(gf, dict):
                        findings_list = gf.get("Findings", [])
            det_entry["findings"] = findings_list
            gd_payload["detectors"].append(det_entry)
    if gd_payload["detectors"]:
        write_json_file(logging_dir / "guardduty_detectors_and_findings.json", gd_payload)

    cfg = session.client("config", region_name=region)
    rules = safe_client_call(manifest, "config:DescribeConfigRules", lambda: cfg.describe_config_rules())
    if isinstance(rules, dict):
        write_json_file(logging_dir / "configservice_describe_config_rules.json", rules)

    cw = session.client("cloudwatch", region_name=region)
    alarm_pages = paginate_all("describe_alarms", cw, manifest, "cloudwatch")
    if alarm_pages:
        write_json_file(logging_dir / "cloudwatch_describe_alarms_pages.json", {"Pages": alarm_pages})

    manifest_path = dest / "manifest.json"

    if fixture_compatible:
        merged_inst = inst_pages or []
        logs_payload = build_central_log_sources_payload(
            account_id=account_id,
            region=region,
            describe_trails_response=trails if isinstance(trails, dict) else None,
            describe_flow_logs_pages=flow_pages or [],
        )
        disc = build_discovered_assets_payload(
            account_id=account_id,
            region=region,
            as_of=collected_at_iso,
            describe_instances_pages=merged_inst,
            describe_db_instances_response=dbs if isinstance(dbs, dict) else None,
            describe_load_balancers_response=lbs if isinstance(lbs, dict) else None,
            list_buckets_response=buckets_resp if isinstance(buckets_resp, dict) else None,
        )
        write_json_file(output_dir / "discovered_assets.json", disc)
        write_json_file(output_dir / "central_log_sources.json", logs_payload)
        # Mirror fixture-shaped companions into the region root next to manifest.json so
        # `assess --provider aws --raw-evidence-dir …/raw/aws/{account}/{region}` matches AwsEvidenceProvider layout.
        write_json_file(dest / "discovered_assets.json", disc)
        write_json_file(dest / "central_log_sources.json", logs_payload)

        events: list[Any] = []
        ct_client = session.client("cloudtrail", region_name=region)
        lookup = safe_client_call(
            manifest,
            "cloudtrail:LookupEvents(fixture)",
            lambda: ct_client.lookup_events(MaxResults=50),
        )
        if isinstance(lookup, dict):
            for ev in lookup.get("Events", []):
                # Omit raw CloudTrailEvent JSON here: it can contain sensitive request payloads.
                events.append(
                    {
                        "event_type": "audit.cloudtrail_lookup_event",
                        "provider": "aws",
                        "actor": str(ev.get("Username") or "unknown"),
                        "asset_id": "org-wide-aws",
                        "resource_id": str(ev.get("EventId") or ev.get("EventName") or ""),
                        "timestamp": str(ev.get("EventTime", "") or ""),
                        "raw_event_ref": f"cloudtrail-lookup:{region}:{ev.get('EventId', '')}",
                        "metadata": {
                            "EventName": ev.get("EventName"),
                            "EventSource": ev.get("EventSource"),
                            "ReadOnly": ev.get("ReadOnly"),
                        },
                    }
                )
        for det in gd_payload.get("detectors", []):
            for f in det.get("findings", []):
                events.append(guardduty_finding_to_semantic_event(f, region=region, account_id=account_id))
        if not events:
            events.append(
                {
                    "event_type": "audit.collection_placeholder",
                    "provider": "aws",
                    "actor": "collect_aws_evidence@internal.local",
                    "asset_id": "org-wide-aws",
                    "resource_id": "placeholder",
                    "timestamp": collected_at_iso,
                    "raw_event_ref": "collect_aws_evidence:placeholder",
                    "metadata": {
                        "note": "No LookupEvents or GuardDuty findings captured; replace with real CloudTrail evidence before correlation."
                    },
                }
            )
        write_json_file(output_dir / "cloud_events.json", events)
        write_json_file(dest / "cloud_events.json", events)

        alerts = build_alert_rules_from_cloudwatch(alarm_pages or [])
        write_json_file(output_dir / "alert_rules.json", alerts)
        write_json_file(dest / "alert_rules.json", alerts)

        _write_canonical_companion_stubs(output_dir)
        _write_canonical_companion_stubs(dest)

    _write_canonical_companion_stubs(dest)
    _write_json_if_missing(
        dest / "discovered_assets.json",
        {"collection": {"source": "aws_collect", "account": account_id, "region": region, "as_of": collected_at_iso}, "assets": []},
    )
    _write_json_if_missing(dest / "cloud_events.json", [])
    _write_json_if_missing(dest / "central_log_sources.json", {"siem": "unknown", "sources": []})
    _write_json_if_missing(dest / "alert_rules.json", {"platform": "unknown", "rules": []})

    write_json_file(manifest_path, manifest.to_dict())

    return manifest_path


def _write_text_if_missing(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(text, encoding="utf-8")


def _write_json_if_missing(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        write_json_file(path, data)


def _write_canonical_companion_stubs(root: Path) -> None:
    """Ensure any raw AWS region root is assessable without hand-created files."""
    _write_text_if_missing(
        root / "declared_inventory.csv",
        "inventory_id,asset_id,name,asset_type,expected_provider,expected_region,expected_private_ip,expected_public_ip,in_boundary,scanner_required,log_required,owner,system_component\n",
    )
    _write_text_if_missing(
        root / "scanner_targets.csv",
        "asset_id,scanner,target_type,hostname,ip,scan_profile,credentialed,notes\n",
    )
    _write_text_if_missing(
        root / "poam.csv",
        "poam_id,weakness_name,controls,raw_severity,status,asset_identifier,notes\n",
    )
    _write_json_if_missing(root / "scanner_findings.json", {"findings": []})
    _write_json_if_missing(root / "tickets.json", {"tickets": []})
