# ══════════════════════════════════════════════════════════════════════════════
# SERVICE CONTROL POLICIES (SCPs)
#
# SCPs act as a permission boundary for the entire AWS account, evaluated
# BEFORE any identity-based policy (IAM). An explicit SCP Deny always wins.
# The management/root account is exempt from SCPs by AWS design — these
# policies only apply to member accounts.
#
# Attachment targets are defined in main.tf.
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# SCP 1: DENY ROOT USER ACTIONS
#
# Problem: Every AWS account has a root user with unrestricted access that
# cannot be restricted by IAM policies. If a member account's root credentials
# are compromised, the attacker has god-mode access to that account.
#
# Solution: Use the SCP layer (which sits above IAM) to deny ALL actions when
# the caller's ARN matches the root user pattern arn:aws:iam::*:root. Because
# SCPs are evaluated before IAM, this is absolute — even if someone has the
# root password and MFA device, no action will succeed.
#
# Note: The management account's own root user is NOT covered by SCPs. That
# account must be hardened out-of-band (hardware MFA, emergency-only break-glass
# process, no access keys).
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_organizations_policy" "deny_root_user_actions" {
  name        = "DenyRootUserActions"
  description = "Denies all API actions performed by the root user in any member account."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyRootUserAllActions"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = ["*"]
        Condition = {
          # StringLike supports the wildcard * in the value, which matches any
          # 12-digit account ID. The :root suffix is the canonical ARN suffix
          # for the AWS account root user — it is immutable and cannot be
          # spoofed by a role or user with a similar name.
          StringLike = {
            "aws:PrincipalArn" = ["arn:aws:iam::*:root"]
          }
        }
      }
    ]
  })

  tags = {
    SCPCategory = "identity-control"
    Severity    = "critical"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 2: DENY SECURITY BASELINE MODIFICATION
#
# Problem: A compromised credential inside a member account could disable
# CloudTrail (erasing audit logs), disable GuardDuty (killing threat detection),
# delete Config rules (hiding compliance drift), or delete the cross-account
# management IAM role (severing management plane access).
#
# Solution: Deny the specific destructive/disable actions on CloudTrail,
# GuardDuty, AWS Config, SecurityHub, and the management IAM roles. An
# ArnNotLike condition carves out the OrganizationAccountAccessRole so the
# management plane can still perform authorized maintenance (e.g., upgrading
# CloudTrail to an org-level trail).
#
# Exemption model: Only arn:aws:iam::*:role/OrganizationAccountAccessRole
# (assumed exclusively from the Root account) and AWS Control Tower roles
# (if applicable) bypass these denies. All other principals — human users,
# application roles, developer roles — are blocked absolutely.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_organizations_policy" "deny_security_baseline_modification" {
  name        = "DenySecurityBaselineModification"
  description = "Blocks member account principals from disabling CloudTrail, GuardDuty, Config, SecurityHub, or management IAM roles."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # ── CloudTrail ──────────────────────────────────────────────────────────
      # Covers both classic trails and CloudTrail Lake event data stores.
      # StopLogging is the most critical action to block; without it an attacker
      # can delete a trail and stop all API-level auditing within seconds.
      {
        Sid    = "DenyCloudTrailModification"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:PutInsightSelectors",
          "cloudtrail:RemoveTags",
          "cloudtrail:DeleteEventDataStore",
          "cloudtrail:UpdateEventDataStore",
          "cloudtrail:DeregisterOrganizationDelegatedAdmin",
        ]
        Resource = ["*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
              "arn:aws:iam::*:role/aws-controltower-AdministratorExecutionRole",
            ]
          }
        }
      },

      # ── GuardDuty ───────────────────────────────────────────────────────────
      # Covers detector deletion, member disassociation, and admin account
      # removal. UpdateDetector with enable=false is particularly dangerous as
      # it silently stops threat detection without deleting the detector.
      {
        Sid    = "DenyGuardDutyModification"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DeleteFilter",
          "guardduty:DeleteIPSet",
          "guardduty:DeleteMembers",
          "guardduty:DeletePublishingDestination",
          "guardduty:DeleteThreatIntelSet",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector",
          "guardduty:UpdateFilter",
          "guardduty:UpdateIPSet",
          "guardduty:UpdatePublishingDestination",
          "guardduty:UpdateThreatIntelSet",
          "guardduty:DisableOrganizationAdminAccount",
          "guardduty:DeleteOrganizationAdminAccount",
        ]
        Resource = ["*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
            ]
          }
        }
      },

      # ── AWS Config ──────────────────────────────────────────────────────────
      # StopConfigurationRecorder disables continuous resource recording.
      # DeleteDeliveryChannel blocks Config from writing to S3/SNS.
      # Together they are the two-step attack to silently disable Config.
      {
        Sid    = "DenyConfigModification"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigRule",
          "config:DeleteConfigurationAggregator",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:DeleteEvaluationResults",
          "config:DeleteOrganizationConfigRule",
          "config:DeleteOrganizationConformancePack",
          "config:DeletePendingAggregationRequest",
          "config:DeleteRemediationConfiguration",
          "config:DeleteRetentionConfiguration",
          "config:DeleteStoredQuery",
          "config:StopConfigurationRecorder",
          "config:UpdateConfigurationAggregator",
          "config:PutConfigurationAggregator",
        ]
        Resource = ["*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
              "arn:aws:iam::*:role/aws-config-role",
              "arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
            ]
          }
        }
      },

      # ── SecurityHub ─────────────────────────────────────────────────────────
      # Disabling SecurityHub silently stops aggregated finding collection
      # from GuardDuty, Inspector, Macie, and custom integrations.
      {
        Sid    = "DenySecurityHubModification"
        Effect = "Deny"
        Action = [
          "securityhub:DeleteHub",
          "securityhub:DisableSecurityHub",
          "securityhub:DisassociateFromAdministratorAccount",
          "securityhub:DisassociateFromMasterAccount",
          "securityhub:DisassociateMembers",
          "securityhub:DeleteMembers",
          "securityhub:DisableImportFindingsForProduct",
          "securityhub:DeleteInvitations",
          "securityhub:DeclineInvitations",
        ]
        Resource = ["*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
            ]
          }
        }
      },

      # ── Management IAM Role Protection ──────────────────────────────────────
      # Prevents any principal (other than OrganizationAccountAccessRole itself)
      # from modifying the cross-account roles that the management plane depends
      # on. An attacker who deletes OrganizationAccountAccessRole severs the
      # management account's ability to access the member account entirely.
      #
      # Resource ARNs are wildcarded on account ID (*) so this covers the
      # specific member account's copy of each role regardless of account ID.
      {
        Sid    = "DenyManagementRoleMutation"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:TagRole",
          "iam:UntagRole",
        ]
        Resource = [
          "arn:aws:iam::*:role/OrganizationAccountAccessRole",
          "arn:aws:iam::*:role/AWSControlTowerExecution",
          "arn:aws:iam::*:role/aws-controltower-*",
        ]
        Condition = {
          # Only OrganizationAccountAccessRole itself (running management-plane
          # automation) may modify these roles.
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
            ]
          }
        }
      },

      # ── Access Analyzer Protection ───────────────────────────────────────────
      # IAM Access Analyzer detects unintended resource exposure. Deleting
      # analyzers prevents detection of overly permissive resource policies.
      {
        Sid    = "DenyAccessAnalyzerDeletion"
        Effect = "Deny"
        Action = [
          "access-analyzer:DeleteAnalyzer",
          "access-analyzer:UpdateFindings",
        ]
        Resource = ["*"]
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
            ]
          }
        }
      },

    ]
  })

  tags = {
    SCPCategory = "security-baseline"
    Severity    = "critical"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# SCP 3: DENY NON-PRIMARY REGIONS
#
# Problem: Without a region boundary, developers or compromised credentials can
# spin up resources in any of AWS's 30+ regions, each with its own security
# posture, logging configuration, and compliance scope. This dramatically
# expands the blast radius of a breach and the cost of compliance auditing.
#
# Solution: Use the NotAction + Condition[StringNotEquals][aws:RequestedRegion]
# pattern. This is the AWS-recommended approach:
#   - "NotAction" lists all global AWS services (IAM, STS, Route53, CloudFront,
#     etc.) that have no regional endpoint and would break if denied by a
#     region-based condition.
#   - "Action: *" with StringNotEquals on aws:RequestedRegion would incorrectly
#     block global service calls because those calls do carry a request region
#     context in some cases.
#   - By combining NotAction (global service exemptions) with the region
#     condition, we get: "Deny everything EXCEPT the global services list, when
#     the requested region is not us-east-1."
#
# Exemption model: OrganizationAccountAccessRole and Control Tower execution
# roles are carved out so management-plane automation can operate globally
# (e.g., enabling GuardDuty in all regions as required by CIS Benchmark).
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_organizations_policy" "deny_non_primary_regions" {
  name        = "DenyNonPrimaryRegions"
  description = "Blocks regional AWS API calls outside of us-east-1. All globally-scoped services are explicitly exempted via NotAction."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllOutsidePrimaryRegion"
        Effect = "Deny"

        # NotAction is an allowlist of services that are EXEMPT from this deny.
        # All services NOT listed here will be denied when requested from a
        # region other than us-east-1.
        #
        # Global services (no regional endpoint):
        NotAction = [
          # ── Identity & Access ───────────────────────────────────────────────
          "iam:*",
          "sts:*",
          "sso:*",
          "sso-admin:*",
          "sso-directory:*",
          "identitystore:*",
          "identitystore-auth:*",

          # ── Billing & Cost Management ────────────────────────────────────────
          "aws-portal:*",
          "billing:*",
          "billingconductor:*",
          "budgets:*",
          "cur:*",
          "ce:*",
          "tax:*",
          "consolidatedbilling:*",
          "freetier:*",

          # ── DNS, Edge & Global CDN ───────────────────────────────────────────
          "route53:*",
          "route53domains:*",
          "route53resolver:ListResolverEndpoints",
          "cloudfront:*",

          # ── Global Edge Security ─────────────────────────────────────────────
          # wafv2 has both regional and global (CloudFront) scopes; listing it
          # here exempts both. Regional WAF associations are still pinned to
          # us-east-1 via the region lockout on compute resources.
          "wafv2:*",
          "waf:*",
          "shield:*",
          "globalaccelerator:*",
          "networkmanager:*",

          # ── Support, Health & Trusted Advisor ───────────────────────────────
          "support:*",
          "trustedadvisor:*",
          "health:*",

          # ── Organizations & Account Management ───────────────────────────────
          "organizations:*",
          "account:*",

          # ── Marketplace & Procurement ────────────────────────────────────────
          "aws-marketplace:*",
          "aws-marketplace-management:*",
          "artifact:*",
          "vendor-insights:*",

          # ── Service Catalog & Resource Sharing ───────────────────────────────
          "servicecatalog:*",

          # ── Chat & Notifications (global control plane) ──────────────────────
          "chatbot:*",

          # ── Pricing & Resource Discovery ─────────────────────────────────────
          "pricing:*",
          "resource-explorer-2:*",

          # ── ACM Public CA (for CloudFront, which requires us-east-1 certs) ──
          # Regional ACM (for ALB/API GW) is still region-locked to us-east-1
          # via the NotAction exclusion below — only global ACM API calls
          # (which have no RequestedRegion) are exempted here.
          "acm:RequestCertificate",
          "acm:DescribeCertificate",
          "acm:ListCertificates",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:ListTagsForCertificate",
          "acm:RemoveTagsFromCertificate",
          "acm:RenewCertificate",
          "acm:GetCertificate",
          "acm:UpdateCertificateOptions",
          "acm:ExportCertificate",
          "acm:ImportCertificate",

          # ── Savings Plans (global commitment, no region scope) ────────────────
          "savingsplans:*",

          # ── License Manager (global entitlements) ─────────────────────────────
          "license-manager:*",

          # ── IQ & Training ──────────────────────────────────────────────────
          "iq:*",
          "training-certification:*",
        ]

        Resource = ["*"]

        Condition = {
          # This condition fires when the API call targets a region that is NOT
          # the primary region. Global services do not set aws:RequestedRegion,
          # so they are immune to this condition regardless of the NotAction list;
          # the NotAction list provides defense-in-depth for edge cases.
          StringNotEquals = {
            "aws:RequestedRegion" = [var.primary_region]
          }

          # Carve out management-plane automation roles so they can perform
          # global operations (e.g., enabling GuardDuty in all regions,
          # bootstrapping new regions for DR, etc.).
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:role/OrganizationAccountAccessRole",
              "arn:aws:iam::*:role/AWSControlTowerExecution",
              "arn:aws:iam::*:role/aws-controltower-AdministratorExecutionRole",
              # Add additional break-glass or automation roles here if needed.
            ]
          }
        }
      }
    ]
  })

  tags = {
    SCPCategory = "region-control"
    Severity    = "high"
  }
}
