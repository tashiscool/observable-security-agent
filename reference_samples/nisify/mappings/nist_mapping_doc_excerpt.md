# NIST CSF 2.0 Evidence Mapping

This document explains how Nisify maps collected evidence to NIST Cybersecurity Framework 2.0 controls, the scoring algorithm, and how to customize mappings for your organization.

## Overview

Nisify uses deterministic, rule-based logic to map evidence to NIST CSF 2.0 controls. There is no machine learning or probabilistic inference - every mapping decision can be traced to explicit rules and evidence.

## NIST CSF 2.0 Structure

The NIST Cybersecurity Framework 2.0 is organized hierarchically:

```
Functions (6)
    Categories (22)
        Subcategories (106)
```

### Functions

| ID | Function | Description |
|----|----------|-------------|
| GV | Govern | Organizational context, risk management strategy, policies |
| ID | Identify | Asset management, risk assessment, improvement |
| PR | Protect | Access control, awareness, data security, platform security |
| DE | Detect | Continuous monitoring, adverse event analysis |
| RS | Respond | Incident management, analysis, mitigation, reporting |
| RC | Recover | Recovery planning, execution, communication |

### Coverage Statistics

- **Total Subcategories**: 106
- **API-Collectible**: 38 subcategories (36%)
- **Manual Evidence Required**: 68 subcategories (64%)
- **Mapped Controls**: 51 subcategories with evidence mapping configurations

## Mapping Process

### 1. Evidence Collection

Evidence is collected from platform APIs and normalized to a common schema:

```json
{
    "id": "uuid",
    "platform": "aws",
    "evidence_type": "mfa_status",
    "collected_at": "2024-01-15T12:00:00Z",
    "raw_data": { ... },
    "metadata": { ... }
}
```
