# Getting Started with AuditKit

Get your first compliance scan running in 5 minutes.

---

## Prerequisites

- Cloud account access (AWS, Azure, or GCP)
- Cloud CLI installed and configured
- 5 minutes

---

## Installation

### Option 1: Download Binary (Fastest)

1. Go to [Releases](https://github.com/guardian-nexus/AuditKit-Community-Edition/releases)
2. Download binary for your OS (Linux, macOS, Windows)
3. Make it executable: `chmod +x auditkit`
4. Run: `./auditkit scan`

### Option 2: Build from Source

```bash
git clone https://github.com/guardian-nexus/AuditKit-Community-Edition
cd AuditKit-Community-Edition/scanner
go build ./cmd/auditkit
./auditkit scan
```

---

## Your First Scan

### AWS

```bash
# 1. Configure AWS credentials
aws configure

# 2. Run scan
./auditkit scan -provider aws -framework soc2

# 3. Generate PDF report
./auditkit scan -provider aws -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [AWS Authentication →](./setup/aws.md)

### Azure

```bash
# 1. Login to Azure
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# 2. Run scan
./auditkit scan -provider azure -framework soc2

# 3. Generate PDF report
./auditkit scan -provider azure -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [Azure Authentication →](./setup/azure.md)

### GCP

```bash
# 1. Login to GCP
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-project-id

# 2. Run scan
./auditkit scan -provider gcp -framework soc2

# 3. Generate PDF report
./auditkit scan -provider gcp -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [GCP Authentication →](./setup/gcp.md)

---

## Understanding Your Results

### Terminal Output

```
AuditKit SOC2 Compliance Scan Results
=====================================
AWS Account: 123456789012
Scan Time: 2025-10-19 14:30:00

Compliance Score: 72.5%
Controls Passed: 46/64

Critical Issues: 3 (FIX IMMEDIATELY)
High Priority: 6
