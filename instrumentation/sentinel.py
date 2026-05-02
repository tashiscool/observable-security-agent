"""Azure Sentinel KQL instrumentation generators."""

from __future__ import annotations

from instrumentation.context import InstrumentationArtifact, InstrumentationInput
from instrumentation.policy_keywords import sentinel_policy_where_has_any


def _asset_filter(asset_id: str) -> str:
    if not asset_id or asset_id == "*":
        return ""
    return f'| where * has "{asset_id}"\n'


def sentinel_instrumentation(inp: InstrumentationInput) -> InstrumentationArtifact:
    st = inp.semantic_type
    af = _asset_filter(inp.asset_id)

    if st == "network.public_admin_port_opened":
        query = f"""AzureActivity
| where OperationNameValue has "networkSecurityGroups/securityRules/write"
| where Properties has "0.0.0.0/0" or Properties has "22" or Properties has "3389"
{sentinel_policy_where_has_any(st).rstrip()}
{af.rstrip()}
| project TimeGenerated, Caller, ResourceId, OperationNameValue, ActivityStatusValue, Properties"""
        name = f"Sentinel — Public admin port / NSG rule ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Analytic rule JSON + incident template + sample detection row export."
    elif st == "network.public_database_port_opened":
        query = f"""AzureActivity
| where OperationNameValue has "firewallRules" or OperationNameValue has "virtualNetworkRules"
| where Properties has "0.0.0.0/0" or Properties has "1433" or Properties has "5432" or Properties has "3306"
{sentinel_policy_where_has_any(st).rstrip()}
{af.rstrip()}
| project TimeGenerated, Caller, ResourceId, OperationNameValue, Properties"""
        name = f"Sentinel — Public SQL listener exposure ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Firewall rule JSON + DBA approval + compensating NSG if any."
    elif st == "network.public_sensitive_service_opened":
        query = f"""AzureActivity
| where OperationNameValue has "networkSecurityGroups/securityRules/write" or OperationNameValue has "firewallRules"
| where Properties has "0.0.0.0/0" or Properties has "::/0"
{sentinel_policy_where_has_any(st).rstrip()}
{af.rstrip()}
| project TimeGenerated, Caller, ResourceId, OperationNameValue, ActivityStatusValue, Properties"""
        name = f"Sentinel — Public sensitive listener / API ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "NSG/GWLB rule export + service owner attestation + compensating detective control."
    elif st == "identity.admin_role_granted":
        query = f"""AuditLogs
| where Category in ("RoleManagement","Policy")
| where OperationName has "Add member to role" or ActivityDisplayName has "Add eligible member"
{af.rstrip()}
| project TimeGenerated, InitiatedBy, TargetResources, OperationName, Result"""
        name = f"Sentinel — Privileged role assignment ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "high"
        ev = "PIM / Access Review export + change record with approver."
    elif st == "identity.mfa_disabled":
        query = f"""AuditLogs
| where OperationName has "Disable" and (TargetResources has "strongAuthentication" or ActivityDisplayName has "MFA")
{af.rstrip()}
| project TimeGenerated, InitiatedBy, TargetUser, OperationName, Result"""
        name = f"Sentinel — MFA disabled / factor reset ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "critical"
        ev = "User risk / sign-in risk investigation + ticket with security decision."
    elif st == "logging.audit_disabled":
        query = f"""AzureActivity
| where OperationNameValue has "Microsoft.Insights/diagnosticSettings" or OperationNameValue has "activityLogAlerts"
| where ActivityStatusValue == "Success"
{af.rstrip()}
| project TimeGenerated, Caller, ResourceId, OperationNameValue, Properties"""
        name = f"Sentinel — Diagnostic settings / audit pipeline change ({inp.asset_id})"
        sched = "*/5 * * * *"
        sev = "critical"
        ev = "Subscription Activity Log export + policy exception approval if applicable."
    elif st == "compute.untracked_asset_created":
        query = f"""AzureActivity
| where OperationNameValue has "Microsoft.Compute/virtualMachines/write"
{af.rstrip()}
| project TimeGenerated, Caller, ResourceId, HTTPRequest, Properties"""
        name = f"Sentinel — New VM without CMDB correlation ({inp.asset_id})"
        sched = "0 */4 * * *"
        sev = "medium"
        ev = "CMDB linkage ticket + resource graph query showing owner tags."
    elif st == "scanner.high_vulnerability_detected":
        query = f"""VulnerabilityFinding
| where Severity in ("High", "Critical")
{af.rstrip()}
| project TimeGenerated, DeviceName, CVEs, Severity, Status, RemediationStatus"""
        name = f"Sentinel — Defender VM / MDE high vuln ({inp.asset_id})"
        sched = "0 6 * * *"
        sev = "high"
        ev = "Machine group exposure + exploitation review workbook export."
    else:
        query = f"""union isfuzzy=true *
| where TimeGenerated > ago(7d)
| where * has "{inp.semantic_type}"
| take 100"""
        name = f"Sentinel — Generic hunt ({inp.semantic_type})"
        sched = "0 * * * *"
        sev = "medium"
        ev = "Map results to control narrative and attach workbook."

    return InstrumentationArtifact(
        platform="Azure Sentinel",
        query_text=query.strip(),
        alert_rule_name=name,
        suggested_schedule=sched,
        suggested_severity=sev,
        suggested_recipients_placeholder="soc@example.com; azure-defender-team@example.com; issm@example.com",
        evidence_required=ev,
    )


def public_admin_port_kql() -> str:
    inp = InstrumentationInput(semantic_type="network.public_admin_port_opened", asset_id="*")
    return sentinel_instrumentation(inp).query_text


def aws_connector_kql() -> str:
    return """AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| where RequestParameters has "0.0.0.0/0"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, EventName, RequestParameters"""
