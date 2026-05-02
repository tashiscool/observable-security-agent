"""AWS CloudTrail / EventBridge instrumentation concepts and lookups."""

from __future__ import annotations

from instrumentation.context import InstrumentationArtifact, InstrumentationInput
from instrumentation.policy_keywords import aws_narrative_policy_footer
from instrumentation.splunk import splunk_instrumentation


def aws_cloudtrail_instrumentation(inp: InstrumentationInput) -> InstrumentationArtifact:
    """Narrative CloudTrail / EventBridge lookup concepts (console + CLI patterns)."""
    st = inp.semantic_type
    res = inp.asset_name or inp.asset_id

    if st == "network.public_admin_port_opened":
        query = f"""CloudTrail lookup concept (multi-event):
- EventName AuthorizeSecurityGroupIngress, CreateSecurityGroup, ModifyNetworkInterfaceAttribute
- Filter RequestParameters / responseElements for 0.0.0.0/0, ::/0, tcp 22, tcp 3389
- Correlate userIdentity.arn, sourceIPAddress, vpcId, groupId for resource {res}
CLI: aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress --max-items 50 --region $AWS_REGION
EventBridge: pattern source=["aws.ec2"] detail-type=["AWS API Call via CloudTrail"] detail.eventName=["AuthorizeSecurityGroupIngress"]{aws_narrative_policy_footer(st)}"""
        name = f"AWS — Public admin port exposure trail ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Exported CloudTrail JSON + Athena query id + IR ticket link."
    elif st == "network.public_database_port_opened":
        query = f"""CloudTrail lookup concept:
- AuthorizeSecurityGroupIngress / AuthorizeSecurityGroupEgress with ports 1433, 5432, 3306, 1521, 27017
- RDS ModifyDBInstance / ModifyDBCluster for publiclyAccessible
Resource scope: {res}
CLI: aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue={res}{aws_narrative_policy_footer(st)}"""
        name = f"AWS — Public database listener trail ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "RDS / SG configuration snapshot + change approval."
    elif st == "network.public_sensitive_service_opened":
        query = f"""CloudTrail lookup concept:
- AuthorizeSecurityGroupIngress with Elastic/Kafka/Docker/K8s/Splunk/RabbitMQ-class ports from policy
- Prefer Config or CSPM exports cross-referenced to SG IDs
Resource scope: {res}{aws_narrative_policy_footer(st)}"""
        name = f"AWS — Public sensitive service trail ({inp.asset_id})"
        sched = "*/15 * * * *"
        sev = "high"
        ev = "Security group revise + threat model update + detective controls for commodity middleware."
    elif st == "identity.admin_role_granted":
        query = f"""CloudTrail lookup concept:
- AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, CreateAccessKey
- IAM Identity Center / SSO AssumeRoleWithSAML where applicable
Principal scope: {res}
CLI: aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy"""
        name = f"AWS — IAM admin policy attachment ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "high"
        ev = "Policy version diff + approver in change system."
    elif st == "identity.mfa_disabled":
        query = f"""CloudTrail lookup concept:
- DeactivateMFADevice, DeleteVirtualMFADevice, SetUserMFAPreference
User / role scope: {res}
EventBridge: detail.eventName prefix DeactivateMFA"""
        name = f"AWS — MFA device removed ({inp.asset_id})"
        sched = "0 * * * *"
        sev = "critical"
        ev = "Support ticket + user acknowledgement + compensating monitoring."
    elif st == "logging.audit_disabled":
        query = f"""CloudTrail lookup concept:
- StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors (exclude management events)
Account / trail scope: {res}
GuardDuty / Security Hub control finding export if triggered"""
        name = f"AWS — CloudTrail / audit subsystem change ({inp.asset_id})"
        sched = "*/5 * * * *"
        sev = "critical"
        ev = "Break-glass record + restored trail configuration screenshot."
    elif st == "compute.untracked_asset_created":
        query = f"""CloudTrail lookup concept:
- RunInstances, CreateFleet, RegisterImage with missing mandatory tags (map to CMDB)
Instance or ASG scope: {res}"""
        name = f"AWS — Untracked compute launch ({inp.asset_id})"
        sched = "0 */4 * * *"
        sev = "medium"
        ev = "Config rule compliance timeline + CMDB update ticket."
    elif st == "scanner.high_vulnerability_detected":
        query = f"""CloudTrail + Security Hub / Inspector concept:
- Security Hub findings ProductNames Inspector, GuardDuty
- Correlate EC2 instanceId {res} with CVEs from partner scanner export
CLI: aws securityhub get-findings --filters ..."""
        name = f"AWS — High vuln evidence chain ({inp.asset_id})"
        sched = "0 6 * * *"
        sev = "high"
        ev = "Inspector/SH finding ARN + exploitation review attachment."
    else:
        query = f"""CloudTrail Event history: filter management events in last 7d containing "{st}" or asset {res}."""
        name = f"AWS — Generic API trail ({inp.semantic_type})"
        sched = "0 * * * *"
        sev = "medium"
        ev = "Map API activity to control family in SSP."

    return InstrumentationArtifact(
        platform="AWS CloudTrail / EventBridge",
        query_text=query.strip(),
        alert_rule_name=name,
        suggested_schedule=sched,
        suggested_severity=sev,
        suggested_recipients_placeholder="soc@example.com; cloudsec@example.com; issm@example.com",
        evidence_required=ev,
    )


def cloudtrail_console_hint(resource_name: str) -> str:
    return (
        f"In AWS Console → CloudTrail → Event history: filter Event name "
        f"AuthorizeSecurityGroupIngress and resource {resource_name}; export JSON for evidence."
    )


def splunk_multicloud_admin_port_spl() -> str:
    inp = InstrumentationInput(semantic_type="network.public_admin_port_opened", asset_id="*")
    return splunk_instrumentation(inp).query_text


def aws_cli_lookup_events_hint() -> str:
    return (
        "aws cloudtrail lookup-events --lookup-attributes "
        "AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress "
        "--max-results 20 --region ${AWS_REGION}"
    )
