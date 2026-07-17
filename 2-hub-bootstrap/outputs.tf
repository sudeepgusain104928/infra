# ══════════════════════════════════════════════════════════════════════════════
# OUTPUTS — 2-hub-bootstrap
#
# These values are the bridge to all subsequent Terraform layers.
# Every layer in the platform will reference the state bucket, lock table,
# and KMS key produced here.
# ══════════════════════════════════════════════════════════════════════════════

# ── KMS Key ───────────────────────────────────────────────────────────────────

output "kms_key_id" {
  description = "Key ID (short form) of the Terraform state CMK."
  value       = aws_kms_key.terraform_state.key_id
}

output "kms_key_arn" {
  description = "Full ARN of the Terraform state CMK. Use as kms_key_id in S3 backend blocks."
  value       = aws_kms_key.terraform_state.arn
}

output "kms_key_alias_arn" {
  description = "ARN of the CMK alias (alias/terraform-state)."
  value       = aws_kms_alias.terraform_state.arn
}

# ── S3 State Bucket ────────────────────────────────────────────────────────────

output "state_bucket_name" {
  description = "Name of the S3 Terraform state bucket. Use as bucket in S3 backend blocks."
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the S3 Terraform state bucket."
  value       = aws_s3_bucket.terraform_state.arn
}

output "state_bucket_region" {
  description = "AWS region where the state bucket is deployed."
  value       = aws_s3_bucket.terraform_state.region
}

# ── DynamoDB Lock Table ────────────────────────────────────────────────────────

output "lock_table_name" {
  description = "Name of the DynamoDB state lock table. Use as dynamodb_table in S3 backend blocks."
  value       = aws_dynamodb_table.terraform_locks.id
}

output "lock_table_arn" {
  description = "ARN of the DynamoDB state lock table."
  value       = aws_dynamodb_table.terraform_locks.arn
}

# ── GitHub Actions OIDC ────────────────────────────────────────────────────────

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider. Reference in spoke account OIDC role trust policies."
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "github_actions_deploy_role_arn" {
  description = "ARN of the GitHub Actions Terraform deploy IAM role. Set as AWS_ROLE_TO_ASSUME in GitHub Actions workflows."
  value       = aws_iam_role.github_actions_deploy.arn
}

output "github_actions_deploy_role_name" {
  description = "Name of the GitHub Actions Terraform deploy IAM role."
  value       = aws_iam_role.github_actions_deploy.name
}

# ── Backend Configuration (rendered) ──────────────────────────────────────────
# Copy this block into the backend configuration of each downstream Terraform
# layer, replacing the 'key' value with a path unique to that layer.
# Example keys:
#   organization-root/terraform.tfstate
#   hub-networking/terraform.tfstate
#   workloads/dev/terraform.tfstate
#   workloads/staging/terraform.tfstate
#   workloads/prod/terraform.tfstate

output "backend_config_rendered" {
  description = "Pre-rendered S3 backend configuration block. Copy into each downstream layer's providers.tf or pass via -backend-config flags."
  value       = <<-EOT
    # ── Paste into downstream providers.tf backend blocks ──────────────────────
    # Replace 'LAYER_NAME' with the path for each specific layer.
    #
    # backend "s3" {
    #   bucket         = "${aws_s3_bucket.terraform_state.id}"
    #   key            = "LAYER_NAME/terraform.tfstate"
    #   region         = "${aws_s3_bucket.terraform_state.region}"
    #   dynamodb_table = "${aws_dynamodb_table.terraform_locks.id}"
    #   encrypt        = true
    #   kms_key_id     = "${aws_kms_key.terraform_state.arn}"
    # }
    #
    # ── Or pass as -backend-config flags ──────────────────────────────────────
    # terraform init \
    #   -backend-config="bucket=${aws_s3_bucket.terraform_state.id}" \
    #   -backend-config="key=LAYER_NAME/terraform.tfstate" \
    #   -backend-config="region=${aws_s3_bucket.terraform_state.region}" \
    #   -backend-config="dynamodb_table=${aws_dynamodb_table.terraform_locks.id}" \
    #   -backend-config="encrypt=true" \
    #   -backend-config="kms_key_id=${aws_kms_key.terraform_state.arn}"
  EOT
}

# ── GitHub Actions Workflow Snippet ────────────────────────────────────────────

output "github_actions_workflow_snippet" {
  description = "Sample GitHub Actions workflow step for OIDC authentication. Paste into .github/workflows/*.yml."
  value       = <<-EOT
    # ── GitHub Actions OIDC Authentication Snippet ────────────────────────────
    # Add these permissions at the workflow or job level:
    #
    # permissions:
    #   id-token: write   # Required for OIDC token request
    #   contents: read    # Required to checkout the repo
    #
    # steps:
    #   - name: Configure AWS credentials via OIDC
    #     uses: aws-actions/configure-aws-credentials@v4
    #     with:
    #       role-to-assume: ${aws_iam_role.github_actions_deploy.arn}
    #       role-session-name: GitHubActions-${{ github.run_id }}
    #       aws-region: ${var.primary_region}
    #
    #   - name: Terraform Init
    #     run: |
    #       terraform init \
    #         -backend-config="bucket=${aws_s3_bucket.terraform_state.id}" \
    #         -backend-config="key=LAYER_NAME/terraform.tfstate" \
    #         -backend-config="region=${var.primary_region}" \
    #         -backend-config="dynamodb_table=${aws_dynamodb_table.terraform_locks.id}" \
    #         -backend-config="encrypt=true" \
    #         -backend-config="kms_key_id=${aws_kms_key.terraform_state.arn}"
  EOT
}

# ── Caller Identity Verification ───────────────────────────────────────────────

output "deployed_in_account_id" {
  description = "The AWS account ID where this bootstrap was applied. Should match var.hub_account_id."
  value       = data.aws_caller_identity.current.account_id
}

output "deployed_in_region" {
  description = "The AWS region where this bootstrap was applied."
  value       = data.aws_region.current.name
}
