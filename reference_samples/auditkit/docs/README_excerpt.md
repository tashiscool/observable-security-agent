# AuditKit - Open-Source Compliance Scanner

**Scan AWS, Azure, GCP, and M365 for SOC2, PCI-DSS, HIPAA, CMMC, CIS Benchmarks, and NIST 800-53 compliance. Get audit-ready reports in minutes.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/AuditKit-Community-Edition)](https://github.com/guardian-nexus/AuditKit-Community-Edition/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.8.2-green.svg)](https://github.com/guardian-nexus/AuditKit-Community-Edition/releases)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

**Need CMMC Level 2, evidence packages, or continuous monitoring?** → [auditkit.io](https://auditkit.io)

---

## Quick Start

```bash
# Install
git clone https://github.com/guardian-nexus/AuditKit-Community-Edition
cd AuditKit-Community-Edition/scanner
go build ./cmd/auditkit

# Scan AWS
./auditkit scan -provider aws -framework soc2          # SOC2 compliance
./auditkit scan -provider aws -framework cis-aws       # CIS security hardening

# Scan Azure
./auditkit scan -provider azure -framework soc2        # SOC2 compliance
./auditkit scan -provider azure -framework cis-azure   # CIS security hardening

# Scan GCP
./auditkit scan -provider gcp -framework soc2          # SOC2 compliance
./auditkit scan -provider gcp -framework cis-gcp       # CIS security hardening

# Generate reports (PDF, HTML, CSV, JSON)
./auditkit scan -provider aws -framework soc2 -format pdf -output aws-soc2.pdf
./auditkit scan -provider gcp -framework pci -format html -output gcp-pci.html
```

**Setup:** [AWS](./site/docs/setup/aws.md) • [Azure](./site/docs/setup/azure.md) • [GCP](./site/docs/setup/gcp.md) • [M365](./site/docs/setup/m365.md)

---

## What It Does

AuditKit scans your cloud infrastructure for compliance gaps and security misconfigurations:

- **Automated Scanning:** ~150 technical controls per framework
- **Multi-Cloud Support:** AWS, Azure, GCP, M365 in one tool
- **Audit-Ready Reports:** PDF/HTML/JSON output with evidence
- **Fix Commands:** Exact CLI/Terraform commands to remediate issues
- **Framework Crosswalk:** One control fix improves multiple frameworks

**What it doesn't do:** Replace auditors, scan for vulnerabilities, or guarantee certification.

**[View Examples →](./site/examples/)** • **[Read Documentation →](./site/docs/)**

---

## Supported Frameworks

### Compliance Frameworks

| Framework | AWS | Azure | GCP | Purpose |
|-----------|-----|-------|-----|---------|
| **SOC2 Type II** | 64 | 64 | 64 | SaaS customer requirements |
| **PCI-DSS v4.0** | All 12 Req | All 12 Req | All 12 Req | Payment card processing |
| **CMMC Level 1** | 17 | 17 | 17 | DoD contractor compliance (FCI) |
| **CMMC Level 2** | 110 | 110 | 110 | DoD contractor compliance (CUI) - [AuditKit](https://auditkit.io/) |
| **NIST 800-53 Rev 5** | ~150 | ~150 | ~150 | Federal contractor requirements / FedRAMP |
| **ISO 27001:2022** | ~60 | ~60 | ~60 | International information security |
| **HIPAA Security Rule** | 70 | 62 | 40 | Healthcare data protection |

### Security Hardening

| Framework | AWS | Azure | GCP | Purpose |
|-----------|-----|-------|-----|---------|
| **CIS Benchmarks** | 126+ | ~40+ | 61 | Industry security best practices |

**[Framework Details →](./site/docs/frameworks/)** • **[What's the difference? →](./site/docs/frameworks/#compliance-vs-security-hardening)**

---

## Community Edition vs AuditKit

| Feature | Community Edition | AuditKit ($297/mo) |
|---------|------|---------------|
| **Cloud Providers** | AWS, Azure, GCP, M365 | Same |
| **Compliance Frameworks** | SOC2, PCI-DSS, CMMC L1, NIST 800-53 | Same |
| **CIS Benchmarks** | AWS (126+ controls) | All clouds when available |
| **GCP Core** | 170+ checks | Same |
| **GCP Advanced** | - | GKE + Vertex AI (32 checks) |
| **On-Prem Scanning** | - | Azure Arc (Experimental) |
| **Multi-Account** | - | AWS Orgs, Azure Mgmt, GCP Folders |
| **CMMC Level 2** | - | 110 practices (CUI handling) |
| **Desktop GUI** | - | Web dashboard at localhost:1337 |
| **Support** | Community (GitHub Issues) | Priority email + 14-day trial |

**[Compare Features →](./site/pricing.md)** • **[Start Free Trial →](https://auditkit.io/)**

---
