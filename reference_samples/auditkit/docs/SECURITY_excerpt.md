# Security Policy

## Overview

AuditKit is designed with security-first principles. This document outlines the permissions required, security considerations, and how to safely use AuditKit in your environment.

**This applies to both AuditKit (free) and AuditKit Pro.**

---

## Permissions Required

### AWS Permissions (Read-Only)

AuditKit requires **READ-ONLY** AWS permissions. No write, modify, or delete permissions are needed.

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetAccountPasswordPolicy",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "s3:ListBuckets",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpnGateways",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "kms:ListKeys",
        "kms:DescribeKey",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "config:DescribeConfigurationRecorders"
      ],
      "Resource": "*"
    }
  ]
}
```

**For Pro - Multi-Account Scanning:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

**What these permissions do:**
- `List*` / `Describe*` / `Get*` - Read configuration data only
- **NO** `Create*` / `Update*` / `Delete*` / `Put*` permissions
