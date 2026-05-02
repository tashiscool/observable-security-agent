"""Splunk SPL instrumentation generators."""

from __future__ import annotations

from instrumentation.context import InstrumentationArtifact, InstrumentationInput
from instrumentation.policy_keywords import splunk_policy_keyword_pipe


def _host_clause(asset_id: str) -> str:
    if not asset_id or asset_id == "*":
        return ""
    return f'(host="{asset_id}" OR asset_id="{asset_id}" OR dest="{asset_id}") AND\n'


def _controls_hint(controls: tuple[str, ...]) -> str:
    return "; ".join(controls) if controls else "Map to SI-4 / SC-7 / AC-2 / AU family per SSP"


def splunk_instrumentation(inp: InstrumentationInput) -> InstrumentationArtifact:
    """Return Splunk SPL and alert metadata for the given semantic type."""
    st = inp.semantic_type
    hc = _host_clause(inp.asset_id)
    ch = _controls_hint(inp.controls)

    if st == "network.public_admin_port_opened":
        query = f"""index=* {hc}(
  eventName="AuthorizeSecurityGroupIngress"
  OR OperationNameValue="Microsoft.Network/networkSecurityGroups/securityRules/write"
  OR protoPayload.methodName="compute.firewalls.insert"
)
("0.0.0.0/0" OR "::/0" OR "22" OR "3389"){splunk_policy_keyword_pipe(st)}
| table _time provider actor resource port source_ip action outcome"""
        name = f"SIEM — Public admin port exposure ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = (
            "Export saved search definition showing enabled=true, cron/alert schedule, and recipients; "
            "attach one sample alert JSON or notable event; link IR/change ticket."
        )
    elif st == "network.public_database_port_opened":
        query = f"""index=* {hc}(
  eventName="AuthorizeSecurityGroupIngress"
  OR OperationNameValue="Microsoft.Sql/servers/firewallRules/write"
  OR protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
)
("0.0.0.0/0" OR "::/0" OR "1433" OR "5432" OR "3306" OR "1521" OR "27017"){splunk_policy_keyword_pipe(st)}
| table _time provider actor resource port source_ip action outcome"""
        name = f"SIEM — Public database listener exposure ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Alert firing sample + firewall rule diff + CAB ticket for rule change."
    elif st == "network.public_sensitive_service_opened":
        query = f"""index=* {hc}(
  eventName="AuthorizeSecurityGroupIngress"
  OR OperationNameValue="Microsoft.Network/networkSecurityGroups/securityRules/write"
  OR protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
)
("0.0.0.0/0" OR "::/0"){splunk_policy_keyword_pipe(st)}
| table _time provider actor resource port source_ip action outcome"""
        name = f"SIEM — Public sensitive service exposure ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Firewall/API exposure review + vendor hardening guide + change record."
    elif st == "identity.admin_role_granted":
        query = f"""index=* {hc}
sourcetype IN ("aws:cloudtrail", "msft:aad:audit", "o365:audit")
(
  eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy")
  OR activityDisplayName="Add member to role*"
  OR Operation="AssignRole"
)
| table _time actor user principal_id policy_arn role outcome"""
        name = f"SIEM — Privileged IAM / role assignment ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "high"
        ev = "SIA for change, approver identity, peer review of IAM JSON/policy diff."
    elif st == "identity.mfa_disabled":
        query = f"""index=* {hc}
sourcetype IN ("aws:cloudtrail", "msft:aad:audit")
(
  eventName IN ("DeactivateMFADevice","DeleteVirtualMFADevice")
  OR activityDisplayName="Disable strong authentication*"
)
| table _time actor user mfa_device outcome"""
        name = f"SIEM — MFA disabled or factor removed ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "critical"
        ev = "Ticket showing business justification + compensating control or MFA re-enable verification."
    elif st == "logging.audit_disabled":
        query = f"""index=* {hc}
sourcetype="aws:cloudtrail"
(eventName IN ("StopLogging","DeleteTrail","UpdateTrail") OR eventName="DeleteEventDataStore")
| table _time actor user trail_name eventName request_parameters outcome"""
        name = f"SIEM — Audit logging disabled or trail deleted ({inp.asset_id})"
        sched = "*/5 * * * *"
        sev = "critical"
        ev = "IR escalation record + restored logging screenshot + privileged break-glass procedure reference."
    elif st == "compute.untracked_asset_created":
        query = f"""index=* {hc}(
  eventName IN ("RunInstances","CreateVirtualMachine","google.compute.instances.insert")
)
| table _time actor user instance_id project region outcome"""
        name = f"SIEM — New compute without CMDB match ({inp.asset_id})"
        sched = "0 */4 * * *"
        sev = "medium"
        ev = "CMDB update ticket + scanner-onboarding evidence + owner attestation."
    elif st == "scanner.high_vulnerability_detected":
        filt = '(severity IN ("high","critical") OR match(_raw, "CVE-*"))'
        if inp.asset_id and inp.asset_id != "*":
            filt = f'({filt}) AND (host="{inp.asset_id}" OR asset_id="{inp.asset_id}")'
        query = f"""index IN (nessus, qualys, tenable, vulnerability) OR sourcetype IN ("nessus:scan", "qualys:vm")
{filt}
| table _time host plugin_id cve_id severity solution_status"""
        name = f"SIEM — High/Critical vuln correlation ({inp.asset_id})"
        sched = "0 6 * * *"
        sev = "high"
        ev = "RA-5(8) exploitation-review query exports + analyst + time window documented in ticket."
    else:
        query = f"""index=* {hc}search="*{inp.semantic_type}*"
| head 500
| table _time host source sourcetype _raw"""
        name = f"SIEM — Generic detection ({inp.semantic_type})"
        sched = "0 * * * *"
        sev = "medium"
        ev = f"Map event to control objectives ({ch}); attach assessor evidence pack."

    return InstrumentationArtifact(
        platform="Splunk",
        query_text=query.strip(),
        alert_rule_name=name,
        suggested_schedule=sched,
        suggested_severity=sev,
        suggested_recipients_placeholder="soc@example.com; cloud-platform-governance@example.com; issm@example.com",
        evidence_required=ev,
    )


def public_admin_port_spl(asset_id: str | None = None) -> str:
    aid = asset_id or "*"
    inp = InstrumentationInput(semantic_type="network.public_admin_port_opened", asset_id=aid)
    return splunk_instrumentation(inp).query_text


def exploitation_review_spl(host: str) -> str:
    return f"""index=* host="{host}"
("CVE-*" OR "kernel" OR "privilege escalation" OR "sudo" OR "sshd" OR "segfault")
| table _time host source sourcetype user src_ip process message"""


def account_provisioning_spl() -> str:
    return """index=* sourcetype IN ("app_audit","fedhr")
(event_type="USER_CREATED" OR event_type="USER_DISABLED" OR event_type="ROLE_CHANGED")
| table _time actor target_user event_type old_role new_role src_ip outcome"""
