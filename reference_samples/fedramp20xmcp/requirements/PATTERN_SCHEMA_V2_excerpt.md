# Pattern Schema V2 - Extended for Evidence Collection

## Overview

This document defines the extended YAML pattern schema that enables patterns to provide comprehensive guidance for all FedRAMP 20x requirements (199 FRRs + 72 KSIs + 50 FRDs = 321 total).

**Goal:** Provide pattern-driven architecture that maintains accuracy and completeness of guidance across 14 supported languages with a unified analysis engine.

## Schema Changes from V1

### V1 Schema (Current - KSI Patterns Only)
```yaml
pattern_id: "family.category.specific"
name: "Pattern Name"
description: "What this pattern detects"
family: "FAMILY_CODE"
severity: "CRITICAL|HIGH|MEDIUM|LOW|INFO"
pattern_type: "import|function|configuration|..."

languages:
  python: {...}
  csharp: {...}
  
finding:
  title_template: "..."
  description_template: "..."
  remediation_template: "..."
  
tags: ["tag1", "tag2"]
nist_controls: ["control-1", "control-2"]
related_ksis: ["KSI-XXX-01"]
```

### V2 Schema (Extended - Full Replacement)
```yaml
pattern_id: "family.category.specific"
name: "Pattern Name"
description: "What this pattern detects"
family: "FAMILY_CODE"
severity: "CRITICAL|HIGH|MEDIUM|LOW|INFO"
pattern_type: "import|function|configuration|..."

# EXISTING: Detection logic
languages:
  python: {...}
  csharp: {...}
  java: {...}
  typescript: {...}
  bicep: {...}
  terraform: {...}
  github_actions: {...}
  azure_pipelines: {...}
  gitlab_ci: {...}

# EXISTING: Finding generation
finding:
  title_template: "..."
  description_template: "..."
  remediation_template: "..."

# NEW: Evidence collection (replaces get_evidence_collection_queries)
evidence_collection:
  azure_monitor_kql:
    - query: "SecurityRecommendation | where ..."
      description: "Monthly vulnerability trends"
      retention_days: 365
  azure_cli:
    - command: "az security pricing list ..."
      description: "Defender for Cloud configuration"
      output_format: "json"
  powershell:
    - script: "Get-AzSecurityPricing | ..."
      description: "Security pricing tier validation"
  rest_api:
    - endpoint: "/subscriptions/{id}/providers/Microsoft.Security/..."
