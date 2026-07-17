# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — ORGANIZATION ROOT
# Executed once from the Root/Management account.
# Creates the OU hierarchy, member accounts, and attaches all SCPs.
# All SCP policy resources are defined in scps.tf.
# ══════════════════════════════════════════════════════════════════════════════

# ── VARIABLES ──────────────────────────────────────────────────────────────────

variable "primary_region" {
  description = "The single AWS region where all workloads are permitted to operate. Enforced via SCP."
  type        = string
  default     = "us-east-1"
}

variable "hub_account_email" {
  description = "Unique root email address for the Hub (Shared Services) AWS account. Must not be used by any other AWS account globally."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.hub_account_email))
    error_message = "hub_account_email must be a valid email address."
  }
}

variable "spoke_accounts" {
  description = "Map of spoke account logical names to their creation parameters. Keys are used to derive OU placement."
  type = map(object({
    email       = string
    environment = string
  }))

  default = {
    dev = {
      email       = "aws+spoke-dev@example.com"
      environment = "development"
    }
    staging = {
      email       = "aws+spoke-staging@example.com"
      environment = "staging"
    }
    prod = {
      email       = "aws+spoke-prod@example.com"
      environment = "production"
    }
  }

  validation {
    condition = alltrue([
      for k, v in var.spoke_accounts :
      contains(["dev", "staging", "prod"], k)
    ])
    error_message = "spoke_accounts keys must be one of: dev, staging, prod."
  }
}

# ── AWS ORGANIZATION ───────────────────────────────────────────────────────────
# If an Organization already exists in the Root account, import it before the
# first apply to avoid an error:
#
#   terraform import aws_organizations_organization.root <org-id>
#   (e.g., terraform import aws_organizations_organization.root o-abc123def456)
#
# The import will adopt the existing org without modifying it.

resource "aws_organizations_organization" "root" {
  # "ALL" enables both Consolidated Billing and all governance features
  # (SCPs, Tag Policies, AI Services opt-out, Backup Policies).
  feature_set = "ALL"

  # Delegate these services to operate across member accounts via Organizations
  # integration. Each principal listed here is granted ListAccounts and related
  # cross-account discovery permissions automatically by Organizations.
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "ram.amazonaws.com",
    "tagpolicies.tag.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
  ]

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
  ]
}

# ── ORGANIZATIONAL UNITS ───────────────────────────────────────────────────────
# Hierarchy:
#
#   Root
#   ├── Core-Infra     (Hub account: networking, security tooling, shared services)
#   └── Workloads      (Parent OU for all application environments)
#       ├── Dev
#       ├── Staging
#       └── Prod

resource "aws_organizations_organizational_unit" "core_infra" {
  name      = "Core-Infra"
  parent_id = aws_organizations_organization.root.roots[0].id

  tags = {
    Purpose = "Hub and shared-services accounts: Transit Gateway Route53 resolver centralized logging security tooling"
  }
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.root.roots[0].id

  tags = {
    Purpose = "Parent container for all workload environment OUs"
  }
}

resource "aws_organizations_organizational_unit" "workloads_dev" {
  name      = "Dev"
  parent_id = aws_organizations_organizational_unit.workloads.id

  tags = { Environment = "development" }
}

resource "aws_organizations_organizational_unit" "workloads_staging" {
  name      = "Staging"
  parent_id = aws_organizations_organizational_unit.workloads.id

  tags = { Environment = "staging" }
}

resource "aws_organizations_organizational_unit" "workloads_prod" {
  name      = "Prod"
  parent_id = aws_organizations_organizational_unit.workloads.id

  tags = { Environment = "production" }
}

# ── MEMBER ACCOUNTS ────────────────────────────────────────────────────────────

resource "aws_organizations_account" "hub" {
  name  = "Hub-SharedServices"
  email = var.hub_account_email

  # Place inside the Core-Infra OU.
  parent_id = aws_organizations_organizational_unit.core_infra.id

  # AWS automatically creates this IAM role in the new account, granting
  # AdministratorAccess assumable from the Root account. This is the mechanism
  # used by 2-hub-bootstrap to operate inside the Hub without static keys.
  role_name = "OrganizationAccountAccessRole"

  iam_user_access_to_billing = "ALLOW"

  lifecycle {
    # Account closure is an irreversible 90-day process initiated through the
    # AWS console. Terraform destroy must never trigger it automatically.
    prevent_destroy = true

    # role_name is immutable after account creation; suppress drift detection.
    ignore_changes = [role_name]
  }

  tags = {
    AccountType = "hub"
    Purpose     = "Shared services: networking Transit Gateway DNS centralized security tooling"
  }
}

# Map each spoke logical name to its environment-specific OU.
# This local keeps the for_each resource below clean and extensible.
locals {
  spoke_ou_map = {
    dev     = aws_organizations_organizational_unit.workloads_dev.id
    staging = aws_organizations_organizational_unit.workloads_staging.id
    prod    = aws_organizations_organizational_unit.workloads_prod.id
  }
}

resource "aws_organizations_account" "spokes" {
  for_each = var.spoke_accounts

  name      = "Spoke-${title(each.key)}"
  email     = each.value.email
  parent_id = local.spoke_ou_map[each.key]
  role_name = "OrganizationAccountAccessRole"

  iam_user_access_to_billing = "ALLOW"

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [role_name]
  }

  tags = {
    AccountType = "spoke"
    Environment = each.value.environment
  }
}

# ── SCP ATTACHMENTS ────────────────────────────────────────────────────────────
# All aws_organizations_policy resources are defined in scps.tf.
# This section only wires them to targets.
#
# Attachment strategy:
#   SCP 1 (Deny Root User)          → Organization Root    (broadest possible scope)
#   SCP 2 (Security Tamper-Proof)   → Core-Infra OU + Workloads OU
#   SCP 3 (Region Lockout)          → Core-Infra OU + Workloads OU
#
# The Root account itself is NEVER subject to SCPs by AWS design; SCPs only
# apply to member accounts. That is why Root account hardening relies on
# external controls (MFA enforcement, CloudTrail, IAM policies, etc.).

resource "aws_organizations_policy_attachment" "deny_root_user_org_root" {
  policy_id = aws_organizations_policy.deny_root_user_actions.id
  target_id = aws_organizations_organization.root.roots[0].id
}

resource "aws_organizations_policy_attachment" "deny_security_tamper_core_infra" {
  policy_id = aws_organizations_policy.deny_security_baseline_modification.id
  target_id = aws_organizations_organizational_unit.core_infra.id
}

resource "aws_organizations_policy_attachment" "deny_security_tamper_workloads" {
  policy_id = aws_organizations_policy.deny_security_baseline_modification.id
  target_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy_attachment" "region_lockout_core_infra" {
  policy_id = aws_organizations_policy.deny_non_primary_regions.id
  target_id = aws_organizations_organizational_unit.core_infra.id
}

resource "aws_organizations_policy_attachment" "region_lockout_workloads" {
  policy_id = aws_organizations_policy.deny_non_primary_regions.id
  target_id = aws_organizations_organizational_unit.workloads.id
}
