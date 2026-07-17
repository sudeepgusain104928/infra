terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }

  # ── PHASE 1 BOOTSTRAP BACKEND ───────────────────────────────────────────────
  # This layer intentionally starts with a local state file because the remote
  # state backend (S3 + DynamoDB) does not exist yet — it is created by
  # 2-hub-bootstrap in the next phase.
  #
  # STATE MIGRATION PATH (run AFTER 2-hub-bootstrap apply completes):
  #
  #   terraform init \
  #     -backend-config="bucket=<value from 2-hub-bootstrap output: state_bucket_name>" \
  #     -backend-config="key=organization-root/terraform.tfstate" \
  #     -backend-config="region=us-east-1" \
  #     -backend-config="dynamodb_table=<value from 2-hub-bootstrap output: lock_table_name>" \
  #     -backend-config="encrypt=true" \
  #     -backend-config="kms_key_id=<value from 2-hub-bootstrap output: kms_key_arn>" \
  #     -migrate-state
  #
  # Terraform will prompt "Do you want to copy existing state to the new backend?"
  # Answer yes. The local terraform.tfstate file can then be deleted.
  backend "local" {
    path = "terraform.tfstate"
  }
}

# Auto-detect the account ID of whoever is running Terraform.
# This removes the need for var.root_account_id entirely — Terraform asks
# AWS "who am I?" and uses the answer both for the failsafe and as an output.
data "aws_caller_identity" "current" {}

provider "aws" {
  region = var.primary_region

  # ── ROOT ACCOUNT PROVIDER FAILSAFE ─────────────────────────────────────────
  # To guard against running against the wrong account, uncomment the line below
  # and replace with your literal Root account ID. Using a data source here
  # causes a provider cycle (the data source needs the provider to exist first).
  #
  # allowed_account_ids = ["123456789012"]

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Layer       = "organization-root"
      Environment = "management"
      Region      = var.primary_region
    }
  }
}
