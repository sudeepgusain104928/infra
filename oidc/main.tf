# ══════════════════════════════════════════════════════════════════════════════
# OIDC — STANDALONE GITHUB ACTIONS TRUST
#
# Provisions the GitHub Actions OIDC provider and a deploy IAM role directly
# in the currently-authenticated AWS account. No new accounts are created and
# no role assumption is required — use your existing CLI credentials.
#
# Quick start:
#   aws sts get-caller-identity          # confirm account
#   terraform init
#   terraform apply
#
# After apply, set one GitHub Actions variable:
#   OIDC_ROLE_ARN = <deploy_role_arn output>
# Then trigger the test-oidc workflow manually.
# ══════════════════════════════════════════════════════════════════════════════

# ── VARIABLES ──────────────────────────────────────────────────────────────────

variable "github_org" {
  description = "GitHub organization (or user) name. Scopes the OIDC trust to your org only."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name. Scopes the OIDC trust to this repository only."
  type        = string
}

variable "primary_region" {
  description = "AWS region where resources are deployed."
  type        = string
  default     = "us-east-1"
}

# ── DATA SOURCES ───────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

# Dynamically retrieve the OIDC thumbprint from GitHub's token endpoint.
# This avoids hardcoding a value that rotates when GitHub's CA changes.
data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

# ── GITHUB ACTIONS OIDC PROVIDER ───────────────────────────────────────────────
#
# Each AWS account needs its own OIDC provider resource. This resource registers
# GitHub as a trusted identity provider so sts:AssumeRoleWithWebIdentity calls
# carrying a GitHub-issued JWT are accepted.
#
# If an OIDC provider for token.actions.githubusercontent.com already exists in
# this account (e.g., created via the console), import it first:
#
#   terraform import aws_iam_openid_connect_provider.github_actions \
#     arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com

resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = {
    Name    = "GitHubActionsOIDC"
    Purpose = "Keyless GitHub Actions authentication via OIDC"
  }
}

# ── OIDC TRUST POLICY ─────────────────────────────────────────────────────────

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid     = "AllowGitHubActionsOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    # Audience must be sts.amazonaws.com — this is what configure-aws-credentials
    # requests by default when calling getIDToken().
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scope to this org/repo across any ref (branch, tag, PR).
    # The sub claim already encodes the owner, so this single condition is
    # sufficient — no separate repository_owner check needed.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:*"]
    }
  }
}

# ── DEPLOY IAM ROLE ────────────────────────────────────────────────────────────
#
# This role is assumed by GitHub Actions workflows via OIDC. The attached
# policy is intentionally minimal — just enough to call sts:GetCallerIdentity
# so the test workflow can verify the trust chain end-to-end.
#
# Extend the policy (or attach managed policies) here as your automation grows.

resource "aws_iam_role" "github_actions_deploy" {
  name                 = "GitHubActionsOIDCDeploy"
  description          = "Assumed by GitHub Actions via OIDC. No static credentials."
  assume_role_policy   = data.aws_iam_policy_document.github_actions_trust.json
  max_session_duration = 3600

  tags = {
    Name       = "GitHubActionsOIDCDeploy"
    GitHubOrg  = var.github_org
    GitHubRepo = var.github_repo
  }
}

# Minimal inline policy: only allows GetCallerIdentity so the test workflow
# can confirm the assumed identity without granting any resource permissions.
resource "aws_iam_role_policy" "github_actions_deploy" {
  name = "OIDCTestPolicy"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowCallerIdentityCheck"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}
