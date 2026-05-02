"""GCP Cloud Logging instrumentation generators."""

from __future__ import annotations

from instrumentation.context import InstrumentationArtifact, InstrumentationInput
from instrumentation.policy_keywords import gcp_policy_keyword_or_block


def _resource_filter(asset_id: str) -> str:
    if not asset_id or asset_id == "*":
        return ""
    return f'AND (resource.labels.instance_id="{asset_id}" OR jsonPayload.asset_id="{asset_id}" OR labels."compute.googleapis.com/resource_name":"{asset_id}")\n'


def gcp_logging_instrumentation(inp: InstrumentationInput) -> InstrumentationArtifact:
    st = inp.semantic_type
    rf = _resource_filter(inp.asset_id)

    if st == "network.public_admin_port_opened":
        query = f"""protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
AND (
  textPayload:"0.0.0.0/0" OR textPayload:"tcp:22" OR textPayload:"tcp:3389"
  OR protoPayload.request:"0.0.0.0/0"
)
{gcp_policy_keyword_or_block(st).rstrip()}
{rf.rstrip()}"""
        name = f"GCP — Public admin port firewall change ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Log sink export + alert policy YAML + IAM change approver."
    elif st == "network.public_database_port_opened":
        query = f"""protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
AND (textPayload:"1433" OR textPayload:"5432" OR textPayload:"3306" OR protoPayload.request:("0.0.0.0/0"))
{gcp_policy_keyword_or_block(st).rstrip()}
{rf.rstrip()}"""
        name = f"GCP — Public database port exposure ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "SQL instance authorized networks diff + DBA sign-off."
    elif st == "network.public_sensitive_service_opened":
        query = f"""protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
AND (
  textPayload:"0.0.0.0/0" OR protoPayload.request:"0.0.0.0/0"
)
{gcp_policy_keyword_or_block(st).rstrip()}
{rf.rstrip()}"""
        name = f"GCP — Public sensitive API / middleware port ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Firewall rule YAML + service architecture review + IR playbooks for commodity ports."
    elif st == "identity.admin_role_granted":
        query = f"""protoPayload.methodName=("cloudresourcemanager.projects.setIamPolicy" OR "iam.serviceAccounts.setIamPolicy")
{rf.rstrip()}"""
        name = f"GCP — IAM policy / admin binding change ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "high"
        ev = "Policy diff JSON + break-glass or CAB reference."
    elif st == "identity.mfa_disabled":
        query = f"""protoPayload.methodName=("google.iam.admin.v1.DeleteSecurityKey" OR "google.iam.admin.v1.UpdateUser" OR "identitytoolkit.*")
severity>=NOTICE
{rf.rstrip()}"""
        name = f"GCP — MFA / second factor disabled ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "critical"
        ev = "Admin activity audit + user communication log."
    elif st == "logging.audit_disabled":
        query = f"""protoPayload.methodName=("logging.sinks.delete" OR "logging.sinks.update" OR "serviceusage.services.disable")
resource.type="audited_resource"
{rf.rstrip()}"""
        name = f"GCP — Audit logging sink or API disabled ({inp.asset_id})"
        sched = "*/5 * * * *"
        sev = "critical"
        ev = "Org policy exception + restored sink screenshot."
    elif st == "compute.untracked_asset_created":
        query = f"""protoPayload.methodName="compute.instances.insert"
{rf.rstrip()}"""
        name = f"GCP — New GCE instance ({inp.asset_id})"
        sched = "0 */4 * * *"
        sev = "medium"
        ev = "Asset inventory sync + labels owner / cost center."
    elif st == "scanner.high_vulnerability_detected":
        query = f"""logName:"containerthreatdetection" OR logName:"vpc_flows" OR textPayload:"CVE-"
(severity>=ERROR OR jsonPayload.severity="HIGH")
{rf.rstrip()}"""
        name = f"GCP — Vuln / threat finding correlation ({inp.asset_id})"
        sched = "0 6 * * *"
        sev = "high"
        ev = "SCC or partner scanner export + remediation ticket."
    else:
        query = f"""resource.type=gce_instance
timestamp>="{inp.timestamp or '1970-01-01T00:00:00Z'}"
{rf.rstrip()}"""
        name = f"GCP — Generic query ({inp.semantic_type})"
        sched = "0 * * * *"
        sev = "medium"
        ev = "Tie logs to SSP control statements."

    return InstrumentationArtifact(
        platform="GCP Cloud Logging",
        query_text=query.strip(),
        alert_rule_name=name,
        suggested_schedule=sched,
        suggested_severity=sev,
        suggested_recipients_placeholder="soc@example.com; gcp-security@example.com; issm@example.com",
        evidence_required=ev,
    )


def public_admin_firewall_query() -> str:
    inp = InstrumentationInput(semantic_type="network.public_admin_port_opened", asset_id="*")
    return gcp_logging_instrumentation(inp).query_text
