# ══════════════════════════════════════════════════════════════════════════════
# OUTPUTS — 1-organization-root
#
# These values are consumed by 2-hub-bootstrap and subsequent layers.
# Reference them with:
#   data "terraform_remote_state" "org" { ... }
# or pass them as -var flags to the next layer's apply.
# ══════════════════════════════════════════════════════════════════════════════

# ── Organization ───────────────────────────────────────────────────────────────

output "organization_id" {
  description = "The unique identifier of the AWS Organization (e.g., o-abc123def456)."
  value       = aws_organizations_organization.root.id
}

output "organization_arn" {
  description = "Full ARN of the AWS Organization."
  value       = aws_organizations_organization.root.arn
}

output "master_account_id" {
  description = "Account ID of the Root/Management account (auto-detected via sts:GetCallerIdentity)."
  value       = aws_organizations_organization.root.master_account_id
}

output "organization_root_id" {
  description = "The ID of the Organization Root (r-xxxx). Used when attaching SCPs at the broadest scope."
  value       = aws_organizations_organization.root.roots[0].id
}

# ── Organizational Units ────────────────────────────────────────────────────────

output "ou_core_infra_id" {
  description = "OU ID of the Core-Infra organizational unit."
  value       = aws_organizations_organizational_unit.core_infra.id
}

output "ou_core_infra_arn" {
  description = "OU ARN of the Core-Infra organizational unit."
  value       = aws_organizations_organizational_unit.core_infra.arn
}

output "ou_workloads_id" {
  description = "OU ID of the parent Workloads organizational unit."
  value       = aws_organizations_organizational_unit.workloads.id
}

output "ou_workloads_dev_id" {
  description = "OU ID of the Workloads/Dev organizational unit."
  value       = aws_organizations_organizational_unit.workloads_dev.id
}

output "ou_workloads_staging_id" {
  description = "OU ID of the Workloads/Staging organizational unit."
  value       = aws_organizations_organizational_unit.workloads_staging.id
}

output "ou_workloads_prod_id" {
  description = "OU ID of the Workloads/Prod organizational unit."
  value       = aws_organizations_organizational_unit.workloads_prod.id
}

# ── Member Account IDs ─────────────────────────────────────────────────────────

output "hub_account_id" {
  description = "Account ID of the Hub (Shared Services) account. Required as var.hub_account_id in 2-hub-bootstrap."
  value       = aws_organizations_account.hub.id
}

output "hub_account_arn" {
  description = "Full ARN of the Hub account."
  value       = aws_organizations_account.hub.arn
}

output "spoke_account_ids" {
  description = "Map of spoke logical names to their AWS account IDs."
  value = {
    for k, v in aws_organizations_account.spokes : k => v.id
  }
}

output "spoke_account_arns" {
  description = "Map of spoke logical names to their full AWS account ARNs."
  value = {
    for k, v in aws_organizations_account.spokes : k => v.arn
  }
}

# ── Cross-Account Role ARNs ────────────────────────────────────────────────────
# Computed ARNs for the OrganizationAccountAccessRole in each member account.
# These can be used directly in assume_role blocks in downstream providers.

output "hub_organization_access_role_arn" {
  description = "ARN of OrganizationAccountAccessRole in the Hub account. Used in 2-hub-bootstrap providers.tf."
  value       = "arn:aws:iam::${aws_organizations_account.hub.id}:role/OrganizationAccountAccessRole"
}

output "spoke_organization_access_role_arns" {
  description = "Map of spoke logical names to OrganizationAccountAccessRole ARNs in each spoke account."
  value = {
    for k, v in aws_organizations_account.spokes :
    k => "arn:aws:iam::${v.id}:role/OrganizationAccountAccessRole"
  }
}

# ── SCP IDs ───────────────────────────────────────────────────────────────────

output "scp_deny_root_user_id" {
  description = "Policy ID of the DenyRootUserActions SCP."
  value       = aws_organizations_policy.deny_root_user_actions.id
}

output "scp_deny_security_tamper_id" {
  description = "Policy ID of the DenySecurityBaselineModification SCP."
  value       = aws_organizations_policy.deny_security_baseline_modification.id
}

output "scp_deny_non_primary_regions_id" {
  description = "Policy ID of the DenyNonPrimaryRegions SCP."
  value       = aws_organizations_policy.deny_non_primary_regions.id
}

# ── Bootstrap Helper ──────────────────────────────────────────────────────────
# Print the exact command to run next after this layer succeeds.

output "next_step_bootstrap_command" {
  description = "Command to execute immediately after this apply to bootstrap the Hub account."
  value       = <<-EOT
    cd ../2-hub-bootstrap && \
    terraform init && \
    terraform apply \
      -var="hub_account_id=${aws_organizations_account.hub.id}" \
      -var="organization_id=${aws_organizations_organization.root.id}"
  EOT
}
