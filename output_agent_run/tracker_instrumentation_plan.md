# Tracker-driven Instrumentation Plan

Generated from open evidence gaps in the logging, alerting, and incident-response groups.

## Centralized logging and local-to-central correlation (AU family)

- Open gaps: **1**
- Controls impacted: `AU-2`, `AU-3`, `AU-6`, `AU-12`
- Linked KSI IDs: `KSI-LOG-01`
- POA&M required: yes

### Required instrumentation actions

- `gap-0006-local-to-central-log-correlation-missing` (row `6`, severity `high`, type `local_to_central_log_correlation_missing`, controls AU-2, AU-3, AU-6, AU-12)
  - Produce: central_log_sources.json plus a local audit log sample correlated with the central index
  - Validate via: AU6_CENTRALIZED_LOG_COVERAGE local-vs-central correlation must show seen_last_24h=true
  - Context: Demonstrate centralized audit log aggregation: provide Splunk dashboards/searches showing CloudTrail, VPC Flow Logs, CloudWatch Logs, and OS auth.log are reaching the SIEM.

## Alert rules, samples, and response actions (SI-4 / IR family)

- Open gaps: **3**
- Controls impacted: `AU-6`, `SI-4`, `SI-4(1)`, `SI-4(4)`, `IR-4`, `IR-6`
- Linked KSI IDs: `KSI-LOG-01`, `KSI-IR-01`
- POA&M required: yes

### Required instrumentation actions

- `gap-0007-alert-sample-missing` (row `7`, severity `high`, type `alert_sample_missing`, controls AU-6, SI-4)
  - Produce: sample_alert_ref pointing at an executed alert export
  - Validate via: SI4_ALERT_INSTRUMENTATION requires sample_alert_ref to be non-empty
  - Context: Provide the alert rules / saved searches with recipient lists (SOC, IR, IAM Governance) and at least one example alert that fired and was actioned.
- `gap-0008-response-action-missing` (row `8`, severity `high`, type `response_action_missing`, controls SI-4(1), SI-4(4))
  - Produce: tickets.json entry citing the alert with documented response
  - Validate via: Run CROSS_DOMAIN_EVENT_CORRELATION (alert -> ticket linkage)
  - Context: List CloudWatch alarms and GuardDuty findings considered "suspicious activity"; map each to a documented response action.
- `gap-0011-response-action-missing` (row `11`, severity `high`, type `response_action_missing`, controls IR-4, IR-6)
  - Produce: tickets.json entry citing the alert with documented response
  - Validate via: Run CROSS_DOMAIN_EVENT_CORRELATION (alert -> ticket linkage)
  - Context: Incident response evidence: any suspected or confirmed incidents in the past 12 months, including US-CERT/CISA notifications and incident closure records.

## Incident response evidence and US-CERT/CISA notifications (IR family)

- Open gaps: **2**
- Controls impacted: `SI-4(1)`, `SI-4(4)`, `IR-4`, `IR-6`
- Linked KSI IDs: `KSI-IR-01`
- POA&M required: yes

### Required instrumentation actions

- `gap-0008-response-action-missing` (row `8`, severity `high`, type `response_action_missing`, controls SI-4(1), SI-4(4))
  - Produce: tickets.json entry citing the alert with documented response
  - Validate via: Run CROSS_DOMAIN_EVENT_CORRELATION (alert -> ticket linkage)
  - Context: List CloudWatch alarms and GuardDuty findings considered "suspicious activity"; map each to a documented response action.
- `gap-0011-response-action-missing` (row `11`, severity `high`, type `response_action_missing`, controls IR-4, IR-6)
  - Produce: tickets.json entry citing the alert with documented response
  - Validate via: Run CROSS_DOMAIN_EVENT_CORRELATION (alert -> ticket linkage)
  - Context: Incident response evidence: any suspected or confirmed incidents in the past 12 months, including US-CERT/CISA notifications and incident closure records.

## Operational guidance

- Confirm centralized log aggregation (Splunk / SIEM / CloudWatch) covers
  every audit source cited above; capture local-vs-central correlation samples.
- For alerting gaps, attach the enabled rule, recipient list, and a recent
  fired-alert sample for each required semantic detection.
- For incident response gaps, attach the IR ticket, response timeline, and
  any US-CERT/CISA notification artifacts.
