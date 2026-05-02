# Agent telemetry instrumentation plan

Deterministic **detection rule stubs** for agent gateways, policy engines, and memory planes. Map `index` / `table` / `logName` to your environment. Language: **suspected** / **blocked attempt** / **requires review** — not asserted compromise.

**Correlation:** `CORR-001`
**Primary semantic context:** `network.public_admin_port_opened` on asset `prod-api-01`

---

## Generic JSON log schema (agent telemetry)

Normalize gateway / policy / memory events to a single schema so Splunk, Sentinel, GCP, and AWS consumers share field names.

```json
{
  "timestamp": "2026-05-01T14:01:00.000Z",
  "agent_id": "support-ticket-agent",
  "event_type": "agent.tool_call",
  "tool_name": "read_tickets",
  "action": "read",
  "target_resource": "https://support.example/tickets/TICK-4477",
  "policy_decision": "allowed",
  "approval_required": false,
  "approval_status": "not_required",
  "risk_level": "low",
  "evidence_ref": "audit://gateway/call-id/audit-001.json"
}
```

**Enumerations:** `policy_decision`: `allowed` | `blocked` | `warned` | `unknown`. `approval_status`: `approved` | `denied` | `missing` | `not_required`. `risk_level`: `low` | `medium` | `high` | `critical`.

---

### SIEM gap: prompt injection & agentic telemetry (action required)

**Heuristic:** no enabled `alert_rules.json` entry matched agentic / prompt-injection keywords. Below are **starter** queries across platforms — tune index/table names and fields to your deployment.

#### Splunk SPL (prompt injection suspected)

```spl
index=agent_security OR sourcetype=agent:policy_violation OR sourcetype=agent:tool_gateway
( violation_type="prompt_injection_suspected"
  OR match(_raw, "(?i)ignore (all )?(previous|prior) instructions")
  OR match(_raw, "(?i)disregard (the )?(above|prior)")
  OR match(_raw, "(?i)export (customer|user) data")
)
| stats count by agent_id, violation_type, source_system
| where count > 0
```
#### Microsoft Sentinel KQL

```kql
let Patterns = dynamic([
    "ignore previous instructions", "disregard prior", "export customer data", "system: you are now"
]);
AgentTelemetry
| where isempty(column_ifexists("violation_type", "")) or violation_type == "prompt_injection_suspected"
| extend body = tostring(column_ifexists("evidence", column_ifexists("raw", "")))
| where body has_any (Patterns) or violation_type == "prompt_injection_suspected"
| summarize alert_count=count() by agent_id, bin(TimeGenerated, 5m)
```
#### Google Cloud Logging query

```text
(
  jsonPayload.event_type="agent.policy_violation"
  OR jsonPayload.violation_type="prompt_injection_suspected"
  OR textPayload=~"ignore previous instructions"
)
AND (
  resource.type="generic_task"
  OR logName=~"agent-gateway"
)
```
#### AWS (EventBridge / CloudTrail Lake / custom bus)

```text
Concept: EventBridge rule on a centralized ``agent-audit`` bus or CloudTrail Lake SQL
on a custom event channel (``detail-type``: ``AgentPolicyViolation`` / ``AgentToolCall``) where:
  - detail.violation_type = "prompt_injection_suspected"
  - OR detail.raw_text matches regex for instruction-override phrases
Target: SNS → SOC queue; input path = SaaS agent gateway normalized to AWS API destination or Firehose S3.
```


### 1. Prompt injection suspected

Correlate with the **same** ticket/thread ID before autonomous tool execution.

#### Splunk SPL

```spl
index=agent_* (sourcetype=agent:policy_violation OR sourcetype=agent:ticket_ingest)
(violation_type="prompt_injection_suspected" OR match(_raw, "(?i)(ignore previous|disregard prior|system override)"))
| stats values(evidence) as samples by agent_id, violation_type
```

#### Microsoft Sentinel KQL

```kql
AgentEvents
| where violation_type == "prompt_injection_suspected" or tostring(RawBody) matches regex "(?i)ignore previous"
| project TimeGenerated, agent_id, violation_type, RawBody
```

#### Google Cloud Logging

```text
(jsonPayload.violation_type="prompt_injection_suspected"
 OR jsonPayload.event_type="agent.ticket.ingest")
AND (textPayload=~"ignore previous" OR jsonPayload.evidence=~"(?i)export customer")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
EventBridge pattern source=custom.agent.gateway, detail-type in AgentPolicyViolation.
Filter: detail.violation_type == prompt_injection_suspected OR detail.evidence matches regex.
CloudTrail Lake: UNION agent custom events ingested to OCSF schema with ocsf.class_uid for application activity.
```


### 2. Unauthorized tool use

#### Splunk SPL

```spl
index=agent_tool_gateway policy_decision="blocked"
 OR (event_type="agent.tool_call" AND match(tool_name, "^(?!read_|draft_).+") AND policy_decision!="allowed")
| stats count by agent_id, tool_name, target_resource
```

#### Microsoft Sentinel KQL

```kql
AgentToolCall
| where policy_decision == "blocked" or violation_type == "unauthorized_tool_use"
| summarize c=count() by agent_id, tool_name, bin(TimeGenerated, 1h)
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.tool_call"
(jsonPayload.policy_decision="blocked" OR jsonPayload.violation_type="unauthorized_tool_use")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Match on custom event detail: policy_decision=blocked OR tool_name NOT IN allow_list from agent identity registry.
EventBridge input transformer sets finding.severity=high when risk_level in (high,critical).
```


### 3. Approval bypass

Treat **allowed** + **missing** approval on destructive classes as highest priority review.

#### Splunk SPL

```spl
index=agent_tool_gateway (approval_required=true AND approval_status="missing" AND policy_decision="allowed")
 OR violation_type="approval_bypass"
| table _time, agent_id, call_id, tool_name, approval_required, approval_status, policy_decision
```

#### Microsoft Sentinel KQL

```kql
AgentToolCall
| where approval_required == true and approval_status in ("missing","") and policy_decision == "allowed"
| project TimeGenerated, agent_id, tool_name
```

#### Google Cloud Logging

```text
jsonPayload.approval_required=true
jsonPayload.approval_status="missing"
(jsonPayload.policy_decision="allowed" OR jsonPayload.policy_decision="warned")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Guardrail: EventBridge rule fires when detail shows high-risk action with approval_status missing
while policy_decision allowed — **requires review** (may be config bug, not bypass).
```


### 4. Agent accessing data outside declared scope

#### Splunk SPL

```spl
index=agent_tool_gateway event_type="agent.tool_call"
| eval scope_ok=if(match(target_resource, "(?i)prod") AND agent_environment!="prod", 0, 1)
| where scope_ok=0 OR match(_raw, "outside allowed_data_scopes")
| stats by agent_id, target_resource
```

#### Microsoft Sentinel KQL

```kql
AgentToolCall
| where isnotempty(target_resource)
| where agent_environment != "prod"
| where target_resource contains "prod" or target_resource contains "/production/"
| summarize c=count() by agent_id, target_resource, bin(TimeGenerated, 1h)
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.tool_call"
(jsonPayload.target_resource=~"/prod/" OR jsonPayload.target_resource=~"arn:aws:.*:prod")
NOT jsonPayload.allowed_scope_match=true
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Compare tool call `target_resource` ARNs against agent's registered `allowed_data_scopes` prefix list
in Parameter Store; Lambda evaluator emits `AgentScopeViolation` event to EventBridge.
```


### 5. PII / secret written to long-term memory

#### Splunk SPL

```spl
index=agent_memory (memory_type IN ("long_term","vector") AND action="write" AND sensitivity IN ("pii","secret"))
(NOT policy_decision IN ("blocked"))
| stats count by agent_id, memory_event_id, policy_decision
```

#### Microsoft Sentinel KQL

```kql
AgentMemory
| where memory_type in ("long_term","vector") and action == "write"
| where sensitivity in ("pii","secret") and policy_decision != "blocked"
| summarize c=count() by agent_id
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.memory"
jsonPayload.action="write"
(jsonPayload.sensitivity="pii" OR jsonPayload.sensitivity="secret")
(jsonPayload.memory_type="long_term" OR jsonPayload.memory_type="vector")
-jsonPayload.policy_decision="blocked"
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Firehose/Lambda on memory audit stream: flag write events with sensitivity pii|secret to durable stores
unless policy_decision=blocked.
```


### 6. Agent using unapproved credentials

#### Splunk SPL

```spl
index=agent_identity OR index=agent_tool_gateway
(match(credentials_ref, "(?i)(admin|root|breakglass|human_user)") OR violation_type="credential_misuse")
| stats by agent_id, credentials_ref
```

#### Microsoft Sentinel KQL

```kql
AgentIdentity
| where credentials_ref matches regex "(?i)admin|breakglass|human_user"
   or violation_type == "credential_misuse"
| project agent_id, credentials_ref
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.identity"
(jsonPayload.credentials_ref=~"(?i)admin|breakglass" OR jsonPayload.violation_type="credential_misuse")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Compare IAM `userIdentity.arn` from downstream cloud API calls (via service-linked role) against
registered agent workload identity; mismatch → `credential_misuse` **suspected**.
```


### 7. Agent disabling logs or modifying permissions

#### Splunk SPL

```spl
index=agent_tool_gateway OR index=cloudtrail (agent_id=*)
( match(lower(action), "(stoplogging|deletetrail|putbucketpolicy|detachrolepolicy|deletepolicy)") OR eventName IN ("StopLogging","DeleteTrail") )
| stats by agent_id, action, eventName
```

#### Microsoft Sentinel KQL

```kql
union AgentToolCall, AWSCloudTrail
| where action has_any ("StopLogging", "DeleteTrail", "PutRolePolicy", "AttachUserPolicy")
   or ActivityType has "Logging"
| where isempty(agent_id) == false
| project TimeGenerated, agent_id, action
```

#### Google Cloud Logging

```text
(protoPayload.methodName=~".*SetIamPolicy.*" OR protoPayload.methodName=~".*Logging.*")
AND (jsonPayload.labels.agent_id!="" OR labels.agent_id!="")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
Join agent session ID (custom header) to CloudTrail `requestParameters` for mutating APIs on
CloudTrail, Config, IAM, or S3 bucket policies. EventBridge composite rule with agent_id present.
```


### 8. Shadow agent identity observed

Requires authoritative **agent registry** export into the SIEM for lookup.

#### Splunk SPL

```spl
index=agent_tool_gateway
| lookup agent_registry agent_id OUTPUT allowed
| where isnull(allowed) OR agent_id NOT match="^[a-z0-9-]+$"
| stats count by agent_id, tool_name
```

#### Microsoft Sentinel KQL

```kql
// Anti-join ToolCall.agent_id to your AgentRegistry custom table when available.
AgentToolCall
| summarize call_count=count() by agent_id, bin(TimeGenerated, 1h)
| sort by call_count desc
| take 100
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.tool_call"
-jsonPayload.agent_registered:true
```

#### AWS (EventBridge / CloudTrail pattern)

```text
API Gateway/Lambda authorizer denies unknown `agent_id`; log **shadow** attempts to security lake
with `shadow_agent=true` for correlation.
```


### 9. Agent making unexpected external network call

#### Splunk SPL

```spl
index=agent_tool_gateway event_type="agent.network" OR (event_type="agent.tool_call" AND match(target_resource, "^https?://"))
| eval ext=if(match(target_resource, "(?i)support\\.example|internal\\.corp"), 0, 1)
| where ext=1
| stats by agent_id, target_resource, call_id
```

#### Microsoft Sentinel KQL

```kql
AgentToolCall
| where target_resource startswith "http"
| where target_resource !has "support.example" and target_resource !has "internal.corp"
| project agent_id, target_resource
```

#### Google Cloud Logging

```text
jsonPayload.event_type="agent.http"
(jsonPayload.host!~"*.internal.corp" AND jsonPayload.host!~"support.example")
```

#### AWS (EventBridge / CloudTrail pattern)

```text
VPC Flow / egress proxy logs joined on agent workload IP + timestamp window with agent_tool_call stream;
flag egress where destination not in approved egress list for that agent class.
```


---

## Evidence collection checklist (agent telemetry)

1. Export **gateway** configuration: allow list, policy bundle version, and deny/warn counters.
2. Attach sample **normalized** JSON events (schema above) for one blocked and one allowed path.
3. Link **agent_id** to change record / security review ticket for the agent class.
4. Store **derivation**: which ticket body / RAG chunk ID preceded each high-risk tool call.
