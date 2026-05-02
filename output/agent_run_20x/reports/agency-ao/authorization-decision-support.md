# Authorization decision support

**Audience:** Agency AO, ISSO, ISSM, security reviewer.

## Considerations for authorization (evidence-only)

- **KSI failures:** Any FAIL status is a material evidence gap for the mapped KSI until remediated or formally handled under assessor/AO agreement.
- **Open critical / high findings:** Require explicit disposition (remediation, POA&M, or formal risk acceptance).
- **POA&M:** Open rows signal accepted residual work with dates and owners in the machine-readable package.
- **Reconciliation:** `aligned` — if `review_required`, resolve manifest gaps before relying on the package as complete.
- **Inherited controls:** Review `inherited-controls-summary.md` against the CSP’s current authorization package.

## Snapshot alignment with executive readiness

**Readiness-style verdict (same rules as executive bundle):** `not_ready`

**Rationale:** 8 KSI(s) in FAIL status. 15 open critical finding(s).

- **System id:** `SYS-OBS-EXAMPLE-001`
- **Assessment output:** `/private/tmp/agent_run`

## POA&M summary (package snapshot)

**Total POA&M rows:** 18

| POA&M ID | Status | Finding ID | Severity | Target completion |
| --- | --- | --- | --- | --- |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION...` | Open | `FIND-SI4-ALERT-INSTRUMENTATIO...` | high | 2026-06-01 |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION...` | Open | `FIND-SI4-ALERT-INSTRUMENTATIO...` | high | 2026-06-01 |
| `POAM-F20X-D-SI4-ALERT-INSTRUMENTATION...` | Open | `FIND-SI4-ALERT-INSTRUMENTATIO...` | high | 2026-06-01 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |
| `POAM-F20X-ACKER-EVIDENCE-GAP-ANALYSIS...` | Open | `FIND-TRACKER-EVIDENCE-GAP-ANA...` | critical | 2026-05-17 |

## Risk acceptance candidates (package fields only)

Findings below are **open** in the package and carry a `risk_acceptance` object. They are candidates for formal AO / risk-owner decision only if program policy allows; this list does not recommend acceptance.

### `FIND-SI4-ALERT-INSTRUMENTATION-7712019CD417`

- **Severity:** high
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-SI4-ALERT-INSTRUMENTATION-3B5CDDC852D6`

- **Severity:** high
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-SI4-ALERT-INSTRUMENTATION-25E596D712C8`

- **Severity:** high
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A3849B0D23AD`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5D7AA2D77EAF`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-2BB8C505F95D`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-A993E5B7AFB7`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-9C44A567F119`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-3FA19ABD06CE`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0E9FED1E409E`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5DE8A547F602`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-0F9750A869F5`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-5BC7696D857A`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-33EE70A2C5D0`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-4BAED87FEE15`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-F27B227E58C1`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-135F006CD5F6`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`

### `FIND-TRACKER-EVIDENCE-GAP-ANALYSIS-6B0E86FC0760`

- **Severity:** critical
- **risk_acceptance (JSON excerpt):** `{"required": false, "accepted_by": null, "expiration_date": null, "conditions": []}`
