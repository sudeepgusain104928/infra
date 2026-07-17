# ══════════════════════════════════════════════════════════════════════════════
# OUTPUTS — oidc
# ══════════════════════════════════════════════════════════════════════════════

output "account_id" {
  description = "AWS account ID where the OIDC provider and role were created."
  value       = data.aws_caller_identity.current.account_id
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider."
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "deploy_role_arn" {
  description = "ARN of the GitHub Actions deploy role. Set this as OIDC_ROLE_ARN in GitHub Actions variables."
  value       = aws_iam_role.github_actions_deploy.arn
}

output "deploy_role_name" {
  description = "Name of the GitHub Actions deploy role."
  value       = aws_iam_role.github_actions_deploy.name
}

output "next_step" {
  description = "Instructions for wiring up the GitHub Actions test workflow."
  value       = <<-EOT
    1. In your GitHub repo go to:
         Settings → Secrets and variables → Actions → Variables

    2. Create (or update) these repository variables:
         OIDC_ROLE_ARN = ${aws_iam_role.github_actions_deploy.arn}
         AWS_REGION    = ${var.primary_region}

    3. Trigger the workflow:
         Actions → Test OIDC Authentication → Run workflow
  EOT
}
