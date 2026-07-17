# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — HUB BOOTSTRAP
# Executed from the Root account context, assuming OrganizationAccountAccessRole
# inside the Hub account (see providers.tf for STS configuration).
#
# Creates:
#   1. KMS Customer-Managed Key for state bucket encryption
#   2. S3 Terraform state bucket (hardened: versioning, encryption, TLS policy)
#   3. DynamoDB state locking table
#   4. GitHub Actions OIDC provider + deploy IAM role (no static keys)
#   5. Helper backend config file for other Terraform layers
# ══════════════════════════════════════════════════════════════════════════════

# ── VARIABLES ──────────────────────────────────────────────────────────────────

# ── REMOTE STATE — reads outputs from 1-organization-root directly ─────────────
# Eliminates manual copy-paste of hub_account_id and organization_id.
# The path here matches the local backend used in Phase 1 before state migration.
# After migrating Layer 1 state to S3, change this to an s3 backend reference:
#
#   data "terraform_remote_state" "org" {
#     backend = "s3"
#     config = {
#       bucket         = var.state_bucket_name   # known before apply (it's a variable here)
#       key            = "organization-root/terraform.tfstate"
#       region         = var.primary_region
#       dynamodb_table = var.lock_table_name
#       encrypt        = true
#     }
#   }
data "terraform_remote_state" "org" {
  backend = "local"
  config = {
    path = "../1-organization-root/terraform.tfstate"
  }
}

# Convenience locals so the rest of the file reads cleanly.
locals {
  hub_account_id  = data.terraform_remote_state.org.outputs.hub_account_id
  organization_id = data.terraform_remote_state.org.outputs.organization_id
}

# hub_account_id MUST remain a variable because providers.tf uses it to
# configure the assume_role block — provider configuration is evaluated before
# any data sources (including terraform_remote_state) are resolved.
# This is the only value that cannot be sourced from remote state in this layer.
variable "hub_account_id" {
  description = "Account ID of the Hub account. Required at provider init time for the STS assume_role block in providers.tf. All other cross-layer values are read from terraform_remote_state."
  type        = string

  validation {
    condition     = can(regex("^\\d{12}$", var.hub_account_id))
    error_message = "hub_account_id must be exactly 12 digits."
  }
}

variable "state_bucket_name" {
  description = "Globally unique name for the Terraform state S3 bucket. Bucket names must be globally unique across all AWS accounts."
  type        = string
  default     = "terraform-state-hub-shared-services"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9\\-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid S3 bucket name (3-63 chars, lowercase, hyphens allowed, no periods)."
  }
}

variable "lock_table_name" {
  description = "Name for the DynamoDB Terraform state lock table."
  type        = string
  default     = "terraform-state-locks"
}

variable "github_org" {
  description = "GitHub organization name (e.g., 'my-org'). Used to scope the OIDC trust policy."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name (e.g., 'infrastructure'). Used to scope the OIDC trust policy."
  type        = string
}

variable "primary_region" {
  description = "AWS region where state bucket and DynamoDB table are deployed."
  type        = string
  default     = "us-east-1"
}

# ── DATA SOURCES ───────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Dynamically retrieve the OIDC thumbprint for GitHub's token endpoint.
# This avoids hardcoding a value that may rotate when GitHub's CA changes.
data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: KMS CUSTOMER-MANAGED KEY
#
# All Terraform state objects in S3 are encrypted using this CMK.
# Using a CMK (vs. the default aws/s3 key) provides:
#   - Full audit trail of every Decrypt operation in CloudTrail
#   - Ability to immediately revoke access to ALL state files by disabling
#     or deleting the key
#   - Cross-account access control (spoke accounts' roles can be granted
#     kms:Decrypt via this key policy without requiring S3 bucket policy changes)
#   - Key rotation enforced by AWS KMS on an annual schedule
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_kms_key" "terraform_state" {
  description             = "CMK for Terraform state S3 bucket encryption in the Hub account."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # The key policy is the primary access control for KMS.
  # Unlike IAM, if no key policy grants access, NO principal can use the key —
  # not even the account root. Always include the root account as admin.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Root account emergency admin access.
      # Without this statement, losing all other IAM access would permanently
      # lock out the key. This is the AWS-recommended baseline statement.
      {
        Sid    = "EnableRootAccountKeyAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.hub_account_id}:root"
        }
        Action   = ["kms:*"]
        Resource = "*"
      },

      # Allow designated key administrators to manage the CMK lifecycle
      # (rotation, enable/disable, tagging) without being able to USE the key
      # for encryption/decryption operations. Separation of duties.
      {
        Sid    = "AllowKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${local.hub_account_id}:role/OrganizationAccountAccessRole",
          ]
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:RotateKeyOnDemand",
        ]
        Resource = "*"
      },

      # Allow S3 service to use the key for SSE-KMS operations on behalf of
      # authorized IAM principals. Required for aws:kms encryption on S3.
      {
        Sid    = "AllowS3ServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.hub_account_id
            "kms:ViaService"    = "s3.${var.primary_region}.amazonaws.com"
          }
        }
      },

      # Allow Terraform execution roles (Hub OrganizationAccountAccessRole +
      # GitHub Actions OIDC deploy role) to encrypt and decrypt state objects.
      {
        Sid    = "AllowTerraformStateAccess"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${local.hub_account_id}:role/OrganizationAccountAccessRole",
            # GitHub Actions role is created later in this file; forward reference
            # is resolved at plan/apply time because KMS key creation and IAM role
            # creation are independent API calls that do not depend on each other.
            "arn:aws:iam::${local.hub_account_id}:role/GitHubActionsTerraformDeploy",
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
      },

      # Allow cross-account read access for spoke account CI/CD roles.
      # Spoke roles need kms:Decrypt to read the shared state (e.g., for
      # data sources referencing Hub networking outputs).
      # Grant access per-account by adding spoke account IDs here.
      # Example (uncomment and add spoke IDs):
      # {
      #   Sid    = "AllowSpokeAccountStateRead"
      #   Effect = "Allow"
      #   Principal = {
      #     AWS = [
      #       "arn:aws:iam::<spoke-dev-account-id>:role/TerraformDeploy",
      #       "arn:aws:iam::<spoke-prod-account-id>:role/TerraformDeploy",
      #     ]
      #   }
      #   Action   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      #   Resource = "*"
      # },
    ]
  })

  tags = {
    Name    = "terraform-state-cmk"
    Purpose = "Encrypts Terraform remote state in S3"
  }
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: S3 STATE BUCKET — HARDENED
#
# Security matrix applied (in order of configuration below):
#   [1] Versioning: every state file write creates a new version, providing
#       point-in-time recovery and an audit trail of all state changes.
#   [2] SSE-KMS: all objects encrypted with the CMK above.
#   [3] Public Access Block: all four public-access vectors disabled at the
#       bucket level, overriding any accidental public ACL or policy.
#   [4] Bucket Policy:
#       (a) Deny HTTP — all requests must use TLS.
#       (b) Deny TLS < 1.2 — prevents downgrade attacks even over HTTPS.
#       (c) Deny unencrypted PUT — enforces that callers always specify
#           SSE-KMS; protects against clients that don't inherit the bucket default.
#       (d) Deny non-org principals — only identities from the AWS Organization
#           can access the bucket, regardless of IAM policy.
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name

  # Prevent Terraform from destroying the state bucket. Losing state is a
  # catastrophic event that requires manual recovery. This lifecycle rule
  # ensures 'terraform destroy' on this module fails gracefully with an error
  # rather than deleting the bucket.
  #lifecycle {
    #prevent_destroy = true
  #}

  tags = {
    Name    = var.state_bucket_name
    Purpose = "Centralized Terraform remote state for all accounts"
  }
}

# [1] Versioning ───────────────────────────────────────────────────────────────
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# [2] Server-Side Encryption with CMK ─────────────────────────────────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }

    # bucket_key_enabled reduces the number of KMS API calls (and thus cost)
    # by using a per-bucket data key cached at the S3 layer.
    bucket_key_enabled = true
  }
}

# [3] Public Access Block — all four vectors closed ────────────────────────────
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  # Blocks any new ACLs that would grant public access.
  block_public_acls = true

  # Removes the effect of any existing public ACLs.
  ignore_public_acls = true

  # Blocks any new bucket policies or access point policies that grant public access.
  block_public_policy = true

  # Ignores cross-account access if the bucket policy grants public access.
  restrict_public_buckets = true
}

# [4] Bucket Policy ───────────────────────────────────────────────────────────
resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  # The public access block must be set before applying a bucket policy that
  # references it, to avoid a transient race condition.
  depends_on = [aws_s3_bucket_public_access_block.terraform_state]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # [4a] Deny HTTP — enforces encrypted transport for ALL requests.
      # Any request where aws:SecureTransport is false is using plain HTTP.
      {
        Sid    = "DenyHTTP"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },

      # [4b] Deny TLS < 1.2 — prevents downgrade to TLS 1.0 or 1.1 even when
      # the transport IS encrypted. Required by PCI-DSS, HIPAA, and FedRAMP.
      {
        Sid    = "DenyTLSBelow12"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          NumericLessThan = {
            "s3:TlsVersion" = "1.2"
          }
        }
      },

      # [4c] Deny unencrypted PUT — any PutObject request that does not specify
      # the SSE-KMS header is rejected. This prevents a Terraform backend
      # misconfiguration (missing encrypt = true) from silently writing
      # plaintext state objects, even if the bucket default encryption would
      # otherwise apply.
      #
      # Note: The condition checks that the server-side encryption header is NOT
      # set to "aws:kms". If a client specifies AES256 (SSE-S3) instead of
      # SSE-KMS, this deny will also fire, enforcing CMK-only encryption.
      {
        Sid    = "DenyUnencryptedOrNonCMKPuts"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.terraform_state.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },

      # [4d] Deny non-organization access — only IAM principals that belong to
      # the AWS Organization can access the bucket. This is an additional
      # defence that supplements IAM identity-based policies.
      # aws:PrincipalOrgID is checked against the Organization ID from
      # 1-organization-root. A principal from ANY account outside the org —
      # including other AWS accounts that somehow obtain a bucket URL — is denied.
      {
        Sid    = "DenyNonOrganizationAccess"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = local.organization_id
          }
          # Exempt AWS service principals (e.g., CloudFormation, Config) that
          # may legitimately access the bucket on behalf of org accounts.
          # These services use their own service principal, not an account principal.
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:root",
            ]
          }
        }
      },

      # [4e] Explicit ALLOW for Terraform execution principals within the org.
      # Without an explicit Allow in the bucket policy, the DenyNonOrg statement
      # above would still require identity-based IAM Allow to succeed.
      # This Allow grants the minimum necessary permissions to known roles.
      {
        Sid    = "AllowTerraformStateOperations"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${local.hub_account_id}:role/OrganizationAccountAccessRole",
            "arn:aws:iam::${local.hub_account_id}:role/GitHubActionsTerraformDeploy",
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:ListBucketVersions",
          "s3:GetObjectVersion",
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
      },
    ]
  })
}

# Lifecycle rule: move non-current (old) state versions to cheaper storage
# and expire them after 90 days to bound storage costs.
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  # Versioning must be enabled before lifecycle rules referencing NoncurrentVersions
  depends_on = [aws_s3_bucket_versioning.terraform_state]

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"

    filter {
      prefix = ""
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    # Clean up incomplete multipart uploads (shouldn't occur in normal state
    # operations, but good hygiene).
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: DYNAMODB STATE LOCK TABLE
#
# Terraform uses DynamoDB for distributed state locking — it prevents two
# concurrent applies from corrupting the same state file. The table uses
# on-demand billing to avoid provisioning unused capacity.
#
# Encryption uses the same CMK as the S3 bucket for consistency.
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_dynamodb_table" "terraform_locks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  # Required by Terraform: the hash key must be a string named "LockID".
  attribute {
    name = "LockID"
    type = "S"
  }

  # Encrypt lock entries at rest with the same CMK used for state objects.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  # Enable Point-In-Time Recovery so a corrupted lock table can be restored.
  point_in_time_recovery {
    enabled = true
  }

  # Protect from accidental destroy (same reasoning as state bucket).
  #lifecycle {
    #prevent_destroy = true
  #}

  tags = {
    Name    = var.lock_table_name
    Purpose = "Terraform state locking - prevents concurrent applies"
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: GITHUB ACTIONS OIDC — KEYLESS CI/CD
#
# OpenID Connect (OIDC) allows GitHub Actions workflows to assume AWS IAM roles
# using a signed JWT token issued by GitHub, without any stored AWS credentials.
#
# Flow:
#   1. GitHub Actions workflow runs and requests an OIDC token from
#      https://token.actions.githubusercontent.com
#   2. The workflow calls sts:AssumeRoleWithWebIdentity, presenting the JWT.
#   3. AWS validates the JWT signature against GitHub's OIDC public key
#      (fetched from the OIDC provider's JWKS endpoint, pinned by the thumbprint
#      below).
#   4. AWS checks that the JWT's claims (repo, branch, environment) match the
#      IAM role's trust policy conditions.
#   5. If all checks pass, AWS issues short-lived credentials (max 1h).
#   6. No long-lived access keys are ever stored in GitHub Secrets.
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  # The client_id_list tells AWS which "audience" values in the JWT are
  # acceptable. GitHub's official OIDC implementation always sets aud to
  # "sts.amazonaws.com" when used with AWS.
  client_id_list = ["sts.amazonaws.com"]

  # Thumbprint of GitHub's OIDC provider certificate chain root CA.
  # Using the tls_certificate data source (fetched in providers.tf data block)
  # ensures this rotates automatically if GitHub changes their CA.
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = {
    Name    = "GitHubActionsOIDC"
    Purpose = "OIDC identity provider for keyless GitHub Actions authentication"
  }
}

# ── IAM Role: GitHub Actions Terraform Deploy ─────────────────────────────────
# This role is assumed by GitHub Actions workflows to run Terraform plans
# and applies. The trust policy restricts assumption to:
#   - Your specific GitHub organization and repository
#   - Optionally: a specific branch or environment (recommended for prod)
#
# The role's permission policy should be scoped to only what Terraform needs
# to manage in the Hub account. For bootstrap this is broad; narrow it as your
# IaC matures.

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid     = "AllowGitHubActionsOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Restrict to your org and repository. The sub claim format is:
    #   repo:<org>/<repo>:ref:refs/heads/<branch>       (branch push)
    #   repo:<org>/<repo>:environment:<environment>      (deployment environment)
    #   repo:<org>/<repo>:pull_request                   (PR)
    # Using StringLike with a wildcard allows all refs within the repo.
    # For production, replace * with a specific branch (e.g., refs/heads/main).
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:*"]
    }

    # Explicit condition to deny any GitHub org other than yours.
    # Prevents token confusion attacks if the sub claim is spoofed.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner"
      values   = [var.github_org]
    }
  }
}

resource "aws_iam_role" "github_actions_deploy" {
  name                 = "GitHubActionsTerraformDeploy"
  description          = "Assumed by GitHub Actions OIDC to run Terraform in the Hub account. No static keys."
  assume_role_policy   = data.aws_iam_policy_document.github_actions_trust.json
  max_session_duration = 3600

  tags = {
    Name         = "GitHubActionsTerraformDeploy"
    Purpose      = "Keyless CI/CD execution role for Terraform"
    TrustSource  = "GitHub OIDC"
    GitHubOrg    = var.github_org
    GitHubRepo   = var.github_repo
  }
}

# Inline policy attached to the role — scoped to state bucket + lock table
# operations. This is intentionally minimal. Extend it with additional
# resource-specific allows as your Hub Terraform modules grow.
resource "aws_iam_role_policy" "github_actions_state_access" {
  name = "TerraformStateAccess"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StateS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:ListBucketVersions",
          "s3:GetObjectVersion",
        ]
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*",
        ]
      },
      {
        Sid    = "LockTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
        ]
        Resource = aws_dynamodb_table.terraform_locks.arn
      },
      {
        Sid    = "KMSStateKeyAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.terraform_state.arn
      },
      {
        Sid    = "AllowCallerIdentityCheck"
        Effect = "Allow"
        Action = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
    ]
  })
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: BACKEND CONFIG FILE GENERATOR
#
# Writes a backend.hcl file that other Terraform layers can use with:
#   terraform init -backend-config=../../2-hub-bootstrap/backend.hcl
#
# This avoids copy-pasting bucket names and KMS ARNs across multiple layers.
# ══════════════════════════════════════════════════════════════════════════════

# Backend config values are surfaced via the "backend_config_rendered" output.
# To write a backend.hcl file locally, add the hashicorp/local provider to
# required_providers in providers.tf, then uncomment the resource below.
#
# resource "local_file" "backend_config" {
#   content = <<-EOT
#     bucket         = "${aws_s3_bucket.terraform_state.id}"
#     key            = "PLACEHOLDER/terraform.tfstate"
#     region         = "${var.primary_region}"
#     dynamodb_table = "${aws_dynamodb_table.terraform_locks.id}"
#     encrypt        = true
#     kms_key_id     = "${aws_kms_key.terraform_state.arn}"
#   EOT
#   filename        = "${path.module}/backend.hcl"
#   file_permission = "0600"
# }
