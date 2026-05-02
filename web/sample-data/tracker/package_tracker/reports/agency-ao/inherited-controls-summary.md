# Inherited controls summary

**Audience:** Agency AO, ISSO, ISSM, security reviewer.

Rows are built from **`authorization_scope.out_of_scope`** entries that typically describe CSP/inherited boundaries. The package does **not** include CSP SOC reports or inherited authorization letters.

| service/provider | inherited authorization status | inherited capability | CSP evidence needed | agency relevance |
| --- | --- | --- | --- | --- |
| Physical data centers | Out of customer configuration scope in this package. | Inherited from cloud service provider; not customer-configurable. | FedRAMP CSP package / agency-required artifacts **not embedded here**. | Agency retains oversight of inherited controls that affect customer security objectives. |
| Provider-managed network edge | Out of customer configuration scope in this package. | Outside customer administrative boundary; evidence limited to customer plane configuration. | FedRAMP CSP package / agency-required artifacts **not embedded here**. | Agency retains oversight of inherited controls that affect customer security objectives. |

### Distinction (how to read the columns)

- **CSP responsibility:** Physical facilities, hypervisor layers, and other items the customer does not configure, as described in out-of-scope rationale.
- **Agency / customer responsibility:** In-scope categories in `authorization_scope` and evidence the customer must produce for KSIs.
- **Inherited cloud provider responsibility:** Controls delivered by the CSP and accepted through the CSP’s authorization; evidence is outside this customer package unless explicitly attached elsewhere.
- **Shared responsibility:** Customer configures logical controls on CSP-provided services; both parties hold obligations described in FedRAMP shared responsibility models (not restated in full here).
