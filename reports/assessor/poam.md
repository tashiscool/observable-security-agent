# Plan of Action and Milestones (POA&M)

Generated from open assessment findings (FedRAMP 20x-style machine fields).

| POA&M ID | Finding | Severity | Target completion | Status |
| --- | --- | --- | --- | --- |
| `POAM-F20X-M8-INVENTORY-RECONCILIATION-D125DF3B89B5` | CM-8 Inventory Reconciliation | high | 2026-06-01 | Open |
| `POAM-F20X-M8-INVENTORY-RECONCILIATION-0D50FAD17FF4` | CM-8 Inventory Reconciliation | high | 2026-06-01 | Open |
| `POAM-F20X-M8-INVENTORY-RECONCILIATION-68B0C754F647` | CM-8 Inventory Reconciliation | high | 2026-06-01 | Open |
| `POAM-F20X-M8-INVENTORY-RECONCILIATION-09301A56ABAB` | CM-8 Inventory Reconciliation | high | 2026-06-01 | Open |
| `POAM-F20X-M8-INVENTORY-RECONCILIATION-0AF02170B8C0` | CM-8 Inventory Reconciliation | high | 2026-06-01 | Open |
| `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-9DC1315A12EF` | RA-5 Scanner Scope Coverage | high | 2026-06-01 | Open |
| `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-F75F50C37987` | RA-5 Scanner Scope Coverage | high | 2026-06-01 | Open |
| `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-F0F54B1CF549` | RA-5 Scanner Scope Coverage | high | 2026-06-01 | Open |
| `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-8458944B2F4F` | RA-5 Scanner Scope Coverage | high | 2026-06-01 | Open |
| `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-FAE6F90D1D4F` | RA-5 Scanner Scope Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-C47704D15448` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-9391EAE84CB0` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-9D89177109CC` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-7CB5A910DFC6` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-5437212041E1` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-1061C0FD039E` | AU-6/AU-12 Centralized Log Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-2D191F21FC9C` | SI-4 Alert Instrumentation Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-BF379FD97CD3` | SI-4 Alert Instrumentation Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-0794DC8E2DE6` | SI-4 Alert Instrumentation Coverage | high | 2026-06-01 | Open |
| `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-40A0D63E2032` | Cross-Domain Security Event Correlation | high | 2026-06-01 | Open |
| `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-C00B2901315A` | Cross-Domain Security Event Correlation | high | 2026-06-01 | Open |
| `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-D115D418FFD3` | Cross-Domain Security Event Correlation | high | 2026-06-01 | Open |
| `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-4A70207D18C5` | Cross-Domain Security Event Correlation | high | 2026-06-01 | Open |
| `POAM-F20X-IND-RA5-EXPLOITATION-REVIEW-B692B740889B` | RA-5(8) High/Critical Vulnerability Exploitation Review | high | 2026-06-01 | Open |
| `POAM-F20X-IND-RA5-EXPLOITATION-REVIEW-0CFD36B39A20` | RA-5(8) High/Critical Vulnerability Exploitation Review | high | 2026-06-01 | Open |
| `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-7910460AAE21` | CM-3/SI-2 Change Evidence Linkage | high | 2026-06-01 | Open |
| `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-80BEAA4357BC` | CM-3/SI-2 Change Evidence Linkage | high | 2026-06-01 | Open |
| `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-9FB9E58AF25F` | CM-3/SI-2 Change Evidence Linkage | high | 2026-06-01 | Open |
| `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-575B41DA0A54` | CM-3/SI-2 Change Evidence Linkage | high | 2026-06-01 | Open |
| `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-B7C85C9F446D` | CM-3/SI-2 Change Evidence Linkage | high | 2026-06-01 | Open |

## Remediation plans

### `POAM-F20X-M8-INVENTORY-RECONCILIATION-D125DF3B89B5` — CM-8 Inventory Reconciliation

- **Finding ID:** `FIND-CM8-INVENTORY-RECONCILIATION-D125DF3B89B5`
- **Controls:** CM-8, CM-8(1), CM-8(3)
- **KSIs:** KSI-INV-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Investigate affected asset(s); confirm boundary placement and authoritative owner.
2. **2026-05-07** (Customer Chief Risk Officer (delegate)): Update declared inventory / IIW; resolve duplicate or stale rows.
3. **2026-05-13** (Customer Chief Risk Officer (delegate)): Assign accountable owner for each in-scope asset row.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Confirm scanner and central logging requirements for updated inventory classes.
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Export refreshed inventory evidence and attach to POA&M milestone.

### `POAM-F20X-M8-INVENTORY-RECONCILIATION-0D50FAD17FF4` — CM-8 Inventory Reconciliation

- **Finding ID:** `FIND-CM8-INVENTORY-RECONCILIATION-0D50FAD17FF4`
- **Controls:** CM-8, CM-8(1), CM-8(3)
- **KSIs:** KSI-INV-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Investigate affected asset(s); confirm boundary placement and authoritative owner.
2. **2026-05-07** (Customer Chief Risk Officer (delegate)): Update declared inventory / IIW; resolve duplicate or stale rows.
3. **2026-05-13** (Customer Chief Risk Officer (delegate)): Assign accountable owner for each in-scope asset row.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Confirm scanner and central logging requirements for updated inventory classes.
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Export refreshed inventory evidence and attach to POA&M milestone.

### `POAM-F20X-M8-INVENTORY-RECONCILIATION-68B0C754F647` — CM-8 Inventory Reconciliation

- **Finding ID:** `FIND-CM8-INVENTORY-RECONCILIATION-68B0C754F647`
- **Controls:** CM-8, CM-8(1), CM-8(3)
- **KSIs:** KSI-INV-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Investigate affected asset(s); confirm boundary placement and authoritative owner.
2. **2026-05-07** (Customer Chief Risk Officer (delegate)): Update declared inventory / IIW; resolve duplicate or stale rows.
3. **2026-05-13** (Customer Chief Risk Officer (delegate)): Assign accountable owner for each in-scope asset row.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Confirm scanner and central logging requirements for updated inventory classes.
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Export refreshed inventory evidence and attach to POA&M milestone.

### `POAM-F20X-M8-INVENTORY-RECONCILIATION-09301A56ABAB` — CM-8 Inventory Reconciliation

- **Finding ID:** `FIND-CM8-INVENTORY-RECONCILIATION-09301A56ABAB`
- **Controls:** CM-8, CM-8(1), CM-8(3)
- **KSIs:** KSI-INV-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Investigate affected asset(s); confirm boundary placement and authoritative owner.
2. **2026-05-07** (Customer Chief Risk Officer (delegate)): Update declared inventory / IIW; resolve duplicate or stale rows.
3. **2026-05-13** (Customer Chief Risk Officer (delegate)): Assign accountable owner for each in-scope asset row.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Confirm scanner and central logging requirements for updated inventory classes.
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Export refreshed inventory evidence and attach to POA&M milestone.

### `POAM-F20X-M8-INVENTORY-RECONCILIATION-0AF02170B8C0` — CM-8 Inventory Reconciliation

- **Finding ID:** `FIND-CM8-INVENTORY-RECONCILIATION-0AF02170B8C0`
- **Controls:** CM-8, CM-8(1), CM-8(3)
- **KSIs:** KSI-INV-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Investigate affected asset(s); confirm boundary placement and authoritative owner.
2. **2026-05-07** (Customer Chief Risk Officer (delegate)): Update declared inventory / IIW; resolve duplicate or stale rows.
3. **2026-05-13** (Customer Chief Risk Officer (delegate)): Assign accountable owner for each in-scope asset row.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Confirm scanner and central logging requirements for updated inventory classes.
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Export refreshed inventory evidence and attach to POA&M milestone.

### `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-9DC1315A12EF` — RA-5 Scanner Scope Coverage

- **Finding ID:** `FIND-RA5-SCANNER-SCOPE-COVERAGE-9DC1315A12EF`
- **Controls:** CA-7, RA-5, RA-5(3), RA-5(5), RA-5(6), SI-2
- **KSIs:** KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Add missing scanner targets for in-scope assets; credentialed scan where required.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Run scan cycle; collect raw scanner output with timestamps.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Attach system-generated scanner configuration export to evidence package.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Validate finding closure against scanner scope coverage evaluation.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Record residual risk or schedule re-scan per CA-7 cadence.

### `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-F75F50C37987` — RA-5 Scanner Scope Coverage

- **Finding ID:** `FIND-RA5-SCANNER-SCOPE-COVERAGE-F75F50C37987`
- **Controls:** CA-7, RA-5, RA-5(3), RA-5(5), RA-5(6), SI-2
- **KSIs:** KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Add missing scanner targets for in-scope assets; credentialed scan where required.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Run scan cycle; collect raw scanner output with timestamps.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Attach system-generated scanner configuration export to evidence package.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Validate finding closure against scanner scope coverage evaluation.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Record residual risk or schedule re-scan per CA-7 cadence.

### `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-F0F54B1CF549` — RA-5 Scanner Scope Coverage

- **Finding ID:** `FIND-RA5-SCANNER-SCOPE-COVERAGE-F0F54B1CF549`
- **Controls:** CA-7, RA-5, RA-5(3), RA-5(5), RA-5(6), SI-2
- **KSIs:** KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Add missing scanner targets for in-scope assets; credentialed scan where required.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Run scan cycle; collect raw scanner output with timestamps.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Attach system-generated scanner configuration export to evidence package.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Validate finding closure against scanner scope coverage evaluation.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Record residual risk or schedule re-scan per CA-7 cadence.

### `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-8458944B2F4F` — RA-5 Scanner Scope Coverage

- **Finding ID:** `FIND-RA5-SCANNER-SCOPE-COVERAGE-8458944B2F4F`
- **Controls:** CA-7, RA-5, RA-5(3), RA-5(5), RA-5(6), SI-2
- **KSIs:** KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Add missing scanner targets for in-scope assets; credentialed scan where required.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Run scan cycle; collect raw scanner output with timestamps.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Attach system-generated scanner configuration export to evidence package.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Validate finding closure against scanner scope coverage evaluation.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Record residual risk or schedule re-scan per CA-7 cadence.

### `POAM-F20X--RA5-SCANNER-SCOPE-COVERAGE-FAE6F90D1D4F` — RA-5 Scanner Scope Coverage

- **Finding ID:** `FIND-RA5-SCANNER-SCOPE-COVERAGE-FAE6F90D1D4F`
- **Controls:** CA-7, RA-5, RA-5(3), RA-5(5), RA-5(6), SI-2
- **KSIs:** KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Add missing scanner targets for in-scope assets; credentialed scan where required.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Run scan cycle; collect raw scanner output with timestamps.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Attach system-generated scanner configuration export to evidence package.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Validate finding closure against scanner scope coverage evaluation.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Record residual risk or schedule re-scan per CA-7 cadence.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-C47704D15448` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-C47704D15448`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-9391EAE84CB0` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-9391EAE84CB0`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-9D89177109CC` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-9D89177109CC`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-7CB5A910DFC6` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-7CB5A910DFC6`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-5437212041E1` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-5437212041E1`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-U6-CENTRALIZED-LOG-COVERAGE-1061C0FD039E` — AU-6/AU-12 Centralized Log Coverage

- **Finding ID:** `FIND-AU6-CENTRALIZED-LOG-COVERAGE-1061C0FD039E`
- **Controls:** AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Configure central log forwarding for affected assets and required event types.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Produce paired local + central log excerpts for the same event IDs.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Validate last_seen / receipt timestamps meet policy window.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Document retention, integrity, and RBAC for the central store.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run AU-6 style coverage evaluation and attach results.

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-2D191F21FC9C` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-2D191F21FC9C`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Implement or enable SIEM detection for the assessed semantic with accountable recipients.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Add on-call / governance distribution lists to the rule.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Generate sample alert payload or saved-search proof with timestamps.
4. **2026-05-22** (Customer Chief Risk Officer (delegate)): Link alert to incident or change response workflow.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run SI-4 alert instrumentation evaluation.

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-BF379FD97CD3` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-BF379FD97CD3`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Implement or enable SIEM detection for the assessed semantic with accountable recipients.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Add on-call / governance distribution lists to the rule.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Generate sample alert payload or saved-search proof with timestamps.
4. **2026-05-22** (Customer Chief Risk Officer (delegate)): Link alert to incident or change response workflow.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run SI-4 alert instrumentation evaluation.

### `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION-0794DC8E2DE6` — SI-4 Alert Instrumentation Coverage

- **Finding ID:** `FIND-SI4-ALERT-INSTRUMENTATION-0794DC8E2DE6`
- **Controls:** AC-2(4), AC-2(7), AU-5, AU-6, CM-10, CM-11, CM-8(3), SI-3, SI-4, SI-4(1), SI-4(16), SI-4(4)
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Implement or enable SIEM detection for the assessed semantic with accountable recipients.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Add on-call / governance distribution lists to the rule.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Generate sample alert payload or saved-search proof with timestamps.
4. **2026-05-22** (Customer Chief Risk Officer (delegate)): Link alert to incident or change response workflow.
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run SI-4 alert instrumentation evaluation.

### `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-40A0D63E2032` — Cross-Domain Security Event Correlation

- **Finding ID:** `FIND-CROSS-DOMAIN-EVENT-CORRELATION-40A0D63E2032`
- **Controls:** AC-17, AC-2, AC-2(1), AC-2(3), AC-2(4), AC-2(7), AC-3, AC-4, AC-5, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), CA-5, CM-3, CM-7, CM-8, CM-8(1), CM-8(3), IA-2, IA-4, IA-5, IR-4, RA-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SI-4
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Ensure central logging is active for assets tied to correlated events.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Enable accountable alerting for observed semantic types.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Open and link response ticket with timestamps to the triggering event.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Export correlation bundle (inventory + scan + log + ticket IDs).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run cross-domain correlation evaluation.

### `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-C00B2901315A` — Cross-Domain Security Event Correlation

- **Finding ID:** `FIND-CROSS-DOMAIN-EVENT-CORRELATION-C00B2901315A`
- **Controls:** AC-17, AC-2, AC-2(1), AC-2(3), AC-2(4), AC-2(7), AC-3, AC-4, AC-5, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), CA-5, CM-3, CM-7, CM-8, CM-8(1), CM-8(3), IA-2, IA-4, IA-5, IR-4, RA-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SI-4
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Ensure central logging is active for assets tied to correlated events.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Enable accountable alerting for observed semantic types.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Open and link response ticket with timestamps to the triggering event.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Export correlation bundle (inventory + scan + log + ticket IDs).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run cross-domain correlation evaluation.

### `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-D115D418FFD3` — Cross-Domain Security Event Correlation

- **Finding ID:** `FIND-CROSS-DOMAIN-EVENT-CORRELATION-D115D418FFD3`
- **Controls:** AC-17, AC-2, AC-2(1), AC-2(3), AC-2(4), AC-2(7), AC-3, AC-4, AC-5, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), CA-5, CM-3, CM-7, CM-8, CM-8(1), CM-8(3), IA-2, IA-4, IA-5, IR-4, RA-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SI-4
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Ensure central logging is active for assets tied to correlated events.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Enable accountable alerting for observed semantic types.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Open and link response ticket with timestamps to the triggering event.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Export correlation bundle (inventory + scan + log + ticket IDs).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run cross-domain correlation evaluation.

### `POAM-F20X-SS-DOMAIN-EVENT-CORRELATION-4A70207D18C5` — Cross-Domain Security Event Correlation

- **Finding ID:** `FIND-CROSS-DOMAIN-EVENT-CORRELATION-4A70207D18C5`
- **Controls:** AC-17, AC-2, AC-2(1), AC-2(3), AC-2(4), AC-2(7), AC-3, AC-4, AC-5, AC-6, AU-12, AU-2, AU-3, AU-3(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-8, AU-9(2), CA-5, CM-3, CM-7, CM-8, CM-8(1), CM-8(3), IA-2, IA-4, IA-5, IR-4, RA-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SI-4
- **KSIs:** KSI-CM-01, KSI-IAM-01, KSI-INV-01, KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Ensure central logging is active for assets tied to correlated events.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Enable accountable alerting for observed semantic types.
3. **2026-05-16** (Customer Chief Risk Officer (delegate)): Open and link response ticket with timestamps to the triggering event.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Export correlation bundle (inventory + scan + log + ticket IDs).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run cross-domain correlation evaluation.

### `POAM-F20X-IND-RA5-EXPLOITATION-REVIEW-B692B740889B` — RA-5(8) High/Critical Vulnerability Exploitation Review

- **Finding ID:** `FIND-RA5-EXPLOITATION-REVIEW-B692B740889B`
- **Controls:** AU-6, IR-4, RA-5(8), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Run generated exploitation-review queries; retain analyst identity and time range.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Export SIEM/log results and attach to vulnerability ticket.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Document analyst or agent conclusion for in-exploitability decision.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Link ticket to scanner finding IDs (`linked_finding_ids`).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run RA-5(8) evaluation with evidence pointers.

### `POAM-F20X-IND-RA5-EXPLOITATION-REVIEW-0CFD36B39A20` — RA-5(8) High/Critical Vulnerability Exploitation Review

- **Finding ID:** `FIND-RA5-EXPLOITATION-REVIEW-0CFD36B39A20`
- **Controls:** AU-6, IR-4, RA-5(8), SI-4
- **KSIs:** KSI-IR-01, KSI-LOG-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Run generated exploitation-review queries; retain analyst identity and time range.
2. **2026-05-10** (Customer Chief Risk Officer (delegate)): Export SIEM/log results and attach to vulnerability ticket.
3. **2026-05-17** (Customer Chief Risk Officer (delegate)): Document analyst or agent conclusion for in-exploitability decision.
4. **2026-05-23** (Customer Chief Risk Officer (delegate)): Link ticket to scanner finding IDs (`linked_finding_ids`).
5. **2026-05-28** (Customer Chief Risk Officer (delegate)): Re-run RA-5(8) evaluation with evidence pointers.

### `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-7910460AAE21` — CM-3/SI-2 Change Evidence Linkage

- **Finding ID:** `FIND-CM3-CHANGE-EVIDENCE-LINKAGE-7910460AAE21`
- **Controls:** CM-3, CM-4, CM-5, CM-6, MA-2, MA-3, MA-4, MA-5, SA-10, SI-2
- **KSIs:** KSI-CM-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Create or link formal change / incident ticket for the assessed event.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Complete security impact analysis (SIA) and testing evidence per CM-3.
3. **2026-05-15** (Customer Chief Risk Officer (delegate)): Obtain documented approval aligned to change class.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Attach deployment evidence (automation receipt or timestamped record).
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Attach verification evidence (post-change scan or health check).

### `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-80BEAA4357BC` — CM-3/SI-2 Change Evidence Linkage

- **Finding ID:** `FIND-CM3-CHANGE-EVIDENCE-LINKAGE-80BEAA4357BC`
- **Controls:** CM-3, CM-4, CM-5, CM-6, MA-2, MA-3, MA-4, MA-5, SA-10, SI-2
- **KSIs:** KSI-CM-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Create or link formal change / incident ticket for the assessed event.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Complete security impact analysis (SIA) and testing evidence per CM-3.
3. **2026-05-15** (Customer Chief Risk Officer (delegate)): Obtain documented approval aligned to change class.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Attach deployment evidence (automation receipt or timestamped record).
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Attach verification evidence (post-change scan or health check).

### `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-9FB9E58AF25F` — CM-3/SI-2 Change Evidence Linkage

- **Finding ID:** `FIND-CM3-CHANGE-EVIDENCE-LINKAGE-9FB9E58AF25F`
- **Controls:** CM-3, CM-4, CM-5, CM-6, MA-2, MA-3, MA-4, MA-5, SA-10, SI-2
- **KSIs:** KSI-CM-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Create or link formal change / incident ticket for the assessed event.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Complete security impact analysis (SIA) and testing evidence per CM-3.
3. **2026-05-15** (Customer Chief Risk Officer (delegate)): Obtain documented approval aligned to change class.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Attach deployment evidence (automation receipt or timestamped record).
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Attach verification evidence (post-change scan or health check).

### `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-575B41DA0A54` — CM-3/SI-2 Change Evidence Linkage

- **Finding ID:** `FIND-CM3-CHANGE-EVIDENCE-LINKAGE-575B41DA0A54`
- **Controls:** CM-3, CM-4, CM-5, CM-6, MA-2, MA-3, MA-4, MA-5, SA-10, SI-2
- **KSIs:** KSI-CM-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Create or link formal change / incident ticket for the assessed event.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Complete security impact analysis (SIA) and testing evidence per CM-3.
3. **2026-05-15** (Customer Chief Risk Officer (delegate)): Obtain documented approval aligned to change class.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Attach deployment evidence (automation receipt or timestamped record).
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Attach verification evidence (post-change scan or health check).

### `POAM-F20X-CM3-CHANGE-EVIDENCE-LINKAGE-B7C85C9F446D` — CM-3/SI-2 Change Evidence Linkage

- **Finding ID:** `FIND-CM3-CHANGE-EVIDENCE-LINKAGE-B7C85C9F446D`
- **Controls:** CM-3, CM-4, CM-5, CM-6, MA-2, MA-3, MA-4, MA-5, SA-10, SI-2
- **KSIs:** KSI-CM-01, KSI-VULN-01
- **Customer impact:** Elevated exposure window with plausible exploitation or audit failure absent timely remediation.
- **Validation for closure:** True

1. **2026-05-02** (Customer Chief Risk Officer (delegate)): Create or link formal change / incident ticket for the assessed event.
2. **2026-05-09** (Customer Chief Risk Officer (delegate)): Complete security impact analysis (SIA) and testing evidence per CM-3.
3. **2026-05-15** (Customer Chief Risk Officer (delegate)): Obtain documented approval aligned to change class.
4. **2026-05-20** (Customer Chief Risk Officer (delegate)): Attach deployment evidence (automation receipt or timestamped record).
5. **2026-05-26** (Customer Chief Risk Officer (delegate)): Attach verification evidence (post-change scan or health check).
