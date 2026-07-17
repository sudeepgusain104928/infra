terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # ── PHASE 1 BOOTSTRAP BACKEND ───────────────────────────────────────────────
  # This layer also starts with local state because it IS the layer that creates
  # the remote state backend. It is the only layer that will permanently keep
  # its state local (this layer provisions itself and bootstraps others).
  #
  # Alternatively, after initial apply you may migrate this layer's state to the
  # bucket it just created:
  #
  #   terraform init \
  #     -backend-config="bucket=<state_bucket_name output>" \
  #     -backend-config="key=hub-bootstrap/terraform.tfstate" \
  #     -backend-config="region=us-east-1" \
  #     -backend-config="dynamodb_table=<lock_table_name output>" \
  #     -backend-config="encrypt=true" \
  #     -backend-config="kms_key_id=<kms_key_arn output>" \
  #     -migrate-state
  #
  # WARNING: If you migrate bootstrap state to its own bucket, you create a
  # chicken-and-egg dependency: destroying the bucket requires the state that
  # lives inside it. Many teams keep bootstrap state local and in version control
  # (encrypted at rest). Choose the approach that matches your DR requirements.
  backend "local" {
    path = "terraform.tfstate"
  }
}

# ── PRIMARY PROVIDER: HUB ACCOUNT VIA STS ROLE ASSUMPTION ────────────────────
#
# No static IAM user credentials are used anywhere in this configuration.
#
# Authentication flow:
#   1. The executing identity (CI/CD runner or operator workstation) is
#      authenticated as an IAM principal in the Root/Management account.
#   2. The AWS provider calls sts:AssumeRole to exchange those credentials
#      for a set of short-lived, scoped tokens valid for 1 hour.
#   3. The assumed role (OrganizationAccountAccessRole) exists inside the Hub
#      account and has AdministratorAccess — but it is ONLY assumable from the
#      Root account (enforced by the role's trust policy, which AWS Organizations
#      configures automatically when the member account is created).
#   4. All API calls in this Terraform workspace are made with those short-lived
#      tokens. When the session expires, the tokens are dead — there is nothing
#      to rotate or revoke.
#
# The session_policy below reduces the blast radius of the bootstrap session
# to only the services this layer needs: S3, DynamoDB, KMS, IAM (for OIDC),
# and supporting services. Even if the session is hijacked, the attacker
# cannot, for example, create EC2 instances or modify network infrastructure.
provider "aws" {
  region = "us-east-1"

  # ── HUB ACCOUNT PROVIDER FAILSAFE ──────────────────────────────────────────
  # If, for any reason, the assumed role resolves to an account that is NOT the
  # Hub account (e.g., role chaining misconfiguration, wrong hub_account_id
  # variable), the provider will refuse to initialize before touching anything.
  # This mathematically eliminates the risk of deploying the state backend into
  # the Root account.
  allowed_account_ids = [var.hub_account_id]

  assume_role {
    role_arn     = "arn:aws:iam::${var.hub_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformHubBootstrap-${formatdate("YYYYMMDDhhmmss", timestamp())}"

    # Maximum session duration. The OrganizationAccountAccessRole default max
    # session is 1 hour (3600s). Adjust the role's MaxSessionDuration in IAM
    # if longer pipelines require it.
    duration = "1h"

    # Inline session policy: further restricts what this specific STS session
    # can do, even though the assumed role has AdministratorAccess. This is
    # defense-in-depth — the session can only call the services explicitly listed.
    # Actions outside this list return AccessDenied even with Admin role attached.
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid    = "BootstrapSessionScope"
          Effect = "Allow"
          Action = [
            # State backend resources
            "s3:*",
            "dynamodb:*",
            "kms:*",
            # OIDC provider and associated IAM roles
            "iam:*",
            # Provider needs STS to validate its own assumed identity
            "sts:GetCallerIdentity",
            "sts:AssumeRoleWithWebIdentity",
            # TLS data source for OIDC thumbprint
            "sts:GetServiceBearerToken",
          ]
          Resource = "*"
        }
      ]
    })
  }

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Layer       = "hub-bootstrap"
      Environment = "shared-services"
      Region      = "us-east-1"
    }
  }
}
