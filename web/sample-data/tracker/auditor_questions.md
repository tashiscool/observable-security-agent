# Auditor questions (evidence-based)

## Control-family prompts

1. **CM-8**: How does authoritative inventory reconcile duplicate declared names, duplicate `asset_id` rows, stale CMDB attributes versus live discovery, and any production-class assets present in cloud discovery that are absent from the declared list?
2. **RA-5**: Is `assessment_tracker` intentionally excluded from vulnerability scanning? If so, where is the approved deviation?
3. **AU-6/AU-12**: Can you provide a local log event from this asset and the same event in the central logging platform?
4. **SI-4**: Which enabled alert rule detects event type `assessment.tracker_loaded`?
5. **CM-3**: Was event `<tmp>/validation_run/agent_run_tracker/scenario_from_tracker/cloud_events.json#0` covered by an approved change ticket?
6. **RA-5(8)**: *missing: no open High/Critical scanner finding id in AssessmentBundle to anchor this question.*
7. **CA-5**: Should this be tracked in the POA&M?

## Assessor workpaper prompts

- **SI4_ALERT_INSTRUMENTATION-GAP-001**: provide evidence that current state `No alert rules are defined while security-relevant semantic events require instrumentation.` has reached target state `Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.`.
- **SI4_ALERT_INSTRUMENTATION-GAP-002**: provide evidence that current state `No enabled alert rule covers logging.audit_disabled.` has reached target state `Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.`.
- **SI4_ALERT_INSTRUMENTATION-GAP-003**: provide evidence that current state `No enabled alert rule covers network.public_admin_port_opened.` has reached target state `Evidence for SI-4, SI-4(1), SI-4(4), SI-4(16) is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.`.
- **CA5_POAM_STATUS-GAP-001**: provide evidence that current state `Continuous monitoring evidence incomplete; new POA&M rows written to poam.csv.` has reached target state `Evidence for CA-5, CA-7, RA-5, CP-9 is complete, system-generated where possible, linked to the affected asset/event/finding population, and retestable by an assessor sample.`.

## Evaluation gaps (verbatim from assessment)

- **SI4_ALERT_INSTRUMENTATION**: No alert rules are defined while security-relevant semantic events require instrumentation.; No enabled alert rule covers logging.audit_disabled.; No enabled alert rule covers network.public_admin_port_opened.
