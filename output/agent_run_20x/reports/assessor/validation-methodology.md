# Validation methodology

**Audience:** 3PAO, FedRAMP reviewer, technical assessor.

## Scope of this document

This section describes how evidence was transformed into the machine-readable package. It does not add facts beyond what the package records.

## Evaluation rollup

- Evaluations from the assessment run are mapped to NIST Rev.5 controls via configured crosswalks, then to KSI identifiers via `rev5_to_20x_ksi`.
- KSI status is rolled up from linked evaluation outcomes using the precedence order in `validation-policy.yaml` at assessment time (not embedded verbatim in this human report).
- Where no evaluation maps to a catalog KSI for this run, the KSI may appear as NOT_APPLICABLE in the machine-readable results.

## Correlation snapshot (from package)

```json
{
  "correlation_id": "CORR-001",
  "overall_result": "FAIL",
  "evidence_chain": {
    "asset_in_inventory": "PASS",
    "scanner_scope": "PASS",
    "central_logging": "PASS",
    "alert_rule": "FAIL",
    "event_correlation": "PASS",
    "exploitation_review": "PASS",
    "change_ticket": "PASS",
    "agent_tool_governance": "PASS",
    "agent_permission_scope": "PASS",
    "agent_memory_context_safety": "PASS",
    "agent_approval_gates": "PASS",
    "agent_policy_violations": "PASS",
    "agent_auditability": "PASS",
    "poam_entry": "OPEN"
  },
  "assessment_summary": "Rolled up from evaluations: AGENT_APPROVAL_GATES, CA5_POAM_STATUS, CM3_CHANGE_EVIDENCE_LINKAGE, CROSS_DOMAIN_EVENT_CORRELATION, RA5_EXPLOITATION_REVIEW, RA5_SCANNER_SCOPE_COVERAGE, SI4_ALERT_INSTRUMENTATION, TRACKER_EVIDENCE_GAP_ANALYSIS (precedence: FAIL, PARTIAL, OPEN, NOT_APPLICABLE, PASS).",
  "evidence_maturity_summary": {
    "automated_ksis": 1,
    "automation_percentage": 8.33,
    "catalog_automation_target_ksis": 10,
    "catalog_automation_percentage": 83.33,
    "ksi_scores": {
      "KSI-IAM-01": 3,
      "KSI-LOG-01": 4,
      "KSI-VULN-01": 3,
      "KSI-CM-01": 3,
      "KSI-INV-01": 3,
      "KSI-IR-01": 3,
      "KSI-REC-01": 2,
      "KSI-SCRM-01": 1,
      "KSI-AGENT-01": 3,
      "KSI-AGENT-02": 3,
      "KSI-AGENT-03": 3,
      "KSI-AGENT-04": 3
    }
  }
}
```

## What this methodology does not do

- It does not perform live API re-validation.
- It does not infer control effectiveness beyond recorded evaluation results and linked artifacts.
