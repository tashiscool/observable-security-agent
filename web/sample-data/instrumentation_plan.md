# Instrumentation plan

**Correlation:** CORR-001
**Semantic type:** `network.public_admin_port_opened`
**Asset:** `prod-api-01` (provider **aws**, ref `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/fixtures/scenario_public_admin_vuln_event/cloud_events.json#0`)
**Controls (from eval bundle):** AC-17, AC-2, AC-2(1), AC-2(3), AC-2(4), AC-2(7), AC-3, AC-4, AC-5, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-5, AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), CA-5, CA-7, CM-10, CM-11, CM-3, CM-4, CM-5, CM-6, CM-7, CM-8, CM-8(1), CM-8(3), IA-2, IA-4, IA-5, IR-4, MA-2, MA-3, MA-4, MA-5, RA-5, RA-5(3), RA-5(5), RA-5(6), RA-5(8), SA-10, SC-7, SC-7(3), SC-7(4), SC-7(5), SI-2, SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)

---

### Splunk

- **Alert rule name:** SIEM — Public admin port exposure (prod-api-01)
- **Suggested schedule:** `*/15 * * * *`
- **Suggested severity:** high
- **Recipients (placeholder):** soc@example.com; cloud-platform-governance@example.com; issm@example.com
- **Evidence to close gap:** Export saved search definition showing enabled=true, cron/alert schedule, and recipients; attach one sample alert JSON or notable event; link IR/change ticket.

```spl
index=* (host="prod-api-01" OR asset_id="prod-api-01" OR dest="prod-api-01") AND
(
  eventName="AuthorizeSecurityGroupIngress"
  OR OperationNameValue="Microsoft.Network/networkSecurityGroups/securityRules/write"
  OR protoPayload.methodName="compute.firewalls.insert"
)
("0.0.0.0/0" OR "::/0" OR "22" OR "3389")
| table _time provider actor resource port source_ip action outcome
```

### Azure Sentinel

- **Alert rule name:** Sentinel — Public admin port / NSG rule (prod-api-01)
- **Suggested schedule:** `*/15 * * * *`
- **Suggested severity:** high
- **Recipients (placeholder):** soc@example.com; azure-defender-team@example.com; issm@example.com
- **Evidence to close gap:** Analytic rule JSON + incident template + sample detection row export.

```kql
AzureActivity
| where OperationNameValue has "networkSecurityGroups/securityRules/write"
| where Properties has "0.0.0.0/0" or Properties has "22" or Properties has "3389"
| where * has "prod-api-01"
| project TimeGenerated, Caller, ResourceId, OperationNameValue, ActivityStatusValue, Properties
```

### GCP Cloud Logging

- **Alert rule name:** GCP — Public admin port firewall change (prod-api-01)
- **Suggested schedule:** `*/15 * * * *`
- **Suggested severity:** high
- **Recipients (placeholder):** soc@example.com; gcp-security@example.com; issm@example.com
- **Evidence to close gap:** Log sink export + alert policy YAML + IAM change approver.

```text
protoPayload.methodName=("compute.firewalls.insert" OR "compute.firewalls.patch")
AND (
  textPayload:"0.0.0.0/0" OR textPayload:"tcp:22" OR textPayload:"tcp:3389"
  OR protoPayload.request:"0.0.0.0/0"
)
AND (resource.labels.instance_id="prod-api-01" OR jsonPayload.asset_id="prod-api-01" OR labels."compute.googleapis.com/resource_name":"prod-api-01")
```

### AWS CloudTrail / EventBridge

- **Alert rule name:** AWS — Public admin port exposure trail (prod-api-01)
- **Suggested schedule:** `*/15 * * * *`
- **Suggested severity:** high
- **Recipients (placeholder):** soc@example.com; cloudsec@example.com; issm@example.com
- **Evidence to close gap:** Exported CloudTrail JSON + Athena query id + IR ticket link.

```text
CloudTrail lookup concept (multi-event):
- EventName AuthorizeSecurityGroupIngress, CreateSecurityGroup, ModifyNetworkInterfaceAttribute
- Filter RequestParameters / responseElements for 0.0.0.0/0, ::/0, tcp 22, tcp 3389
- Correlate userIdentity.arn, sourceIPAddress, vpcId, groupId for resource prod-api-01
CLI: aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress --max-items 50 --region $AWS_REGION
EventBridge: pattern source=["aws.ec2"] detail-type=["AWS API Call via CloudTrail"] detail.eventName=["AuthorizeSecurityGroupIngress"]
```

### Evidence collection checklist

1. Export saved search / analytic rule / log-based metric configuration showing **enabled** status.
2. Capture suggested recipients or distribution list IDs used in production.
3. Attach one sample detection, notable, or finding tied to the asset and time window.
4. Link IR or change ticket demonstrating review, approval, and closure where applicable.
