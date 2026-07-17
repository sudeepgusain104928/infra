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

  backend "local" {
    path = "terraform.tfstate"
  }
}

# ── PRIMARY PROVIDER: CURRENT ACCOUNT ─────────────────────────────────────────
# Uses the credentials already present in the environment (AWS CLI profile,
# environment variables, or instance profile). No role assumption — resources
# are created directly in whatever account is currently authenticated.
#
# Run:  aws sts get-caller-identity   to verify before applying.
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Layer       = "oidc"
      Environment = "management"
    }
  }
}
