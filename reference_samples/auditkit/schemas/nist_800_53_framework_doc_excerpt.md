# NIST 800-53 Rev 5

NIST Special Publication 800-53 Revision 5 guide.

---

## Overview

**NIST 800-53** is a catalog of security and privacy controls for federal information systems.

**Who needs it:** Federal contractors, FedRAMP Cloud Service Providers  
**Certification:** Not a certification itself (used by FedRAMP, FISMA)  
**Total controls:** ~1,000 controls  
**AuditKit coverage:** ~150 automated technical controls  
**What's not covered:** ~850 organizational/policy controls

---

## How AuditKit Uses 800-53

**Framework crosswalk:** AuditKit maps existing SOC2, PCI-DSS, and CMMC controls to NIST 800-53 control families.

**Example:**
```
Your SOC2 control: CC6.6 - MFA enforcement

Maps to NIST 800-53:
- IA-2: Identification and Authentication
- IA-2(1): Multi-Factor Authentication
- IA-5: Authenticator Management
```

**Benefit:** Run one scan, see compliance across all frameworks

---

## Control Families

NIST 800-53 has 20 control families. AuditKit covers technical controls in 19 families:

### AC - Access Control
**AuditKit checks:** IAM policies, MFA, least privilege, access key rotation

**Example controls:**
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-17: Remote Access

### AU - Audit and Accountability
**AuditKit checks:** CloudTrail, logging, log retention, audit trails

**Example controls:**
- AU-2: Event Logging
- AU-3: Content of Audit Records
- AU-12: Audit Record Generation

### CA - Assessment, Authorization, & Monitoring
**AuditKit checks:** Security Hub, Config, compliance monitoring

**Example controls:**
- CA-7: Continuous Monitoring

### CM - Configuration Management
**AuditKit checks:** Config baselines, change tracking, patch management

**Example controls:**
- CM-2: Baseline Configuration
- CM-6: Configuration Settings

### IA - Identification and Authentication
**AuditKit checks:** MFA, password policies, authenticator management

**Example controls:**
- IA-2: Identification and Authentication
- IA-5: Authenticator Management

### IR - Incident Response
**AuditKit checks:** GuardDuty, Defender, Security Command Center, alerting

**Example controls:**
- IR-4: Incident Handling
- IR-6: Incident Reporting

### MA - Maintenance
**AuditKit checks:** Systems Manager, Update Management, maintenance windows

**Example controls:**
- MA-2: Controlled Maintenance

### MP - Media Protection
**AuditKit checks:** Storage encryption, secure deletion policies

**Example controls:**
- MP-5: Media Transport

### PE - Physical and Environmental Protection
**What AuditKit checks:** Limited - mostly manual verification

### PL - Planning
**What AuditKit checks:** Limited - mostly organizational policies

### PM - Program Management
**What AuditKit checks:** Limited - mostly organizational policies

### PS - Personnel Security
**What AuditKit checks:** Limited - mostly organizational policies

### RA - Risk Assessment
**AuditKit checks:** Vulnerability scanning, threat detection

**Example controls:**
- RA-5: Vulnerability Monitoring and Scanning

### SA - System and Services Acquisition
**What AuditKit checks:** Limited - mostly organizational policies

### SC - System and Communications Protection
**AuditKit checks:** Encryption, network segmentation, firewalls, TLS

**Example controls:**
