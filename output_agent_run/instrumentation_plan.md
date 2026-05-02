# Instrumentation plan

**Correlation:** CORR-001
**Semantic type:** `assessment.tracker_loaded`
**Asset:** `assessment_tracker` (provider **assessment_tracker**, ref `/Users/tkhan/IdeaProjects/security-infra/observable-security-agent/output_agent_run/scenario_from_tracker/cloud_events.json#0`)
**Controls (from eval bundle):** AC-2, AC-2(4), AC-2(7), AC-3, AC-4, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-5, AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9, AU-9(2), CA-5, CA-7, CM-10, CM-11, CM-3, CM-4, CM-5, CM-6, CM-8, CM-8(1), CM-8(3), CP-10, CP-9, IA-5, IR-4, MA-2, MA-3, MA-4, MA-5, RA-5, RA-5(3), RA-5(5), RA-5(6), RA-5(8), SA-10, SA-9, SC-28, SC-7, SI-12, SI-2, SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)

---

### Splunk

- **Alert rule name:** SIEM — Generic detection (assessment.tracker_loaded)
- **Suggested schedule:** `0 * * * *`
- **Suggested severity:** medium
- **Recipients (placeholder):** soc@example.com; cloud-platform-governance@example.com; issm@example.com
- **Evidence to close gap:** Map event to control objectives (AC-2; AC-2(4); AC-2(7); AC-3; AC-4; AC-6; AU-12; AU-2; AU-3; AU-3(1); AU-5; AU-6; AU-6(1); AU-6(3); AU-7; AU-8; AU-9; AU-9(2); CA-5; CA-7; CM-10; CM-11; CM-3; CM-4; CM-5; CM-6; CM-8; CM-8(1); CM-8(3); CP-10; CP-9; IA-5; IR-4; MA-2; MA-3; MA-4; MA-5; RA-5; RA-5(3); RA-5(5); RA-5(6); RA-5(8); SA-10; SA-9; SC-28; SC-7; SI-12; SI-2; SI-3; SI-4; SI-4(1); SI-4(16); SI-4(4)); attach assessor evidence pack.

```spl
index=* (host="assessment_tracker" OR asset_id="assessment_tracker" OR dest="assessment_tracker") AND
search="*assessment.tracker_loaded*"
| head 500
| table _time host source sourcetype _raw
```

### Azure Sentinel

- **Alert rule name:** Sentinel — Generic hunt (assessment.tracker_loaded)
- **Suggested schedule:** `0 * * * *`
- **Suggested severity:** medium
- **Recipients (placeholder):** soc@example.com; azure-defender-team@example.com; issm@example.com
- **Evidence to close gap:** Map results to control narrative and attach workbook.

```kql
union isfuzzy=true *
| where TimeGenerated > ago(7d)
| where * has "assessment.tracker_loaded"
| take 100
```

### GCP Cloud Logging

- **Alert rule name:** GCP — Generic query (assessment.tracker_loaded)
- **Suggested schedule:** `0 * * * *`
- **Suggested severity:** medium
- **Recipients (placeholder):** soc@example.com; gcp-security@example.com; issm@example.com
- **Evidence to close gap:** Tie logs to SSP control statements.

```text
resource.type=gce_instance
timestamp>="2026-05-02T08:03:44Z"
AND (resource.labels.instance_id="assessment_tracker" OR jsonPayload.asset_id="assessment_tracker" OR labels."compute.googleapis.com/resource_name":"assessment_tracker")
```

### AWS CloudTrail / EventBridge

- **Alert rule name:** AWS — Generic API trail (assessment.tracker_loaded)
- **Suggested schedule:** `0 * * * *`
- **Suggested severity:** medium
- **Recipients (placeholder):** soc@example.com; cloudsec@example.com; issm@example.com
- **Evidence to close gap:** Map API activity to control family in SSP.

```text
CloudTrail Event history: filter management events in last 7d containing "assessment.tracker_loaded" or asset assessment_tracker.
```

### Evidence collection checklist

1. Export saved search / analytic rule / log-based metric configuration showing **enabled** status.
2. Capture suggested recipients or distribution list IDs used in production.
3. Attach one sample detection, notable, or finding tied to the asset and time window.
4. Link IR or change ticket demonstrating review, approval, and closure where applicable.
