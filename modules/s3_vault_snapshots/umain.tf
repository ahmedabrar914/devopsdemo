data "aws_caller_identity" "current" {}

############################################
# S3 bucket
############################################
resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

############################################
# Locals: KMS policy statements (SAFE)
############################################
locals {
  kms_root_statement = {
    Sid    = "EnableRootPermissions"
    Effect = "Allow"
    Principal = {
      AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
    }
    Action   = "kms:*"
    Resource = "*"
  }

  # Only included when vault_role_arn is non-empty
  kms_vault_role_statement = var.vault_role_arn != "" ? {
    Sid    = "AllowVaultRoleUseOfKey"
    Effect = "Allow"
    Principal = {
      AWS = var.vault_role_arn
    }
    Action = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    Resource = "*"
  } : null
}

############################################
# KMS key (customer managed) + alias
############################################
resource "aws_kms_key" "this" {
  description             = "CMK for Vault auto-snapshots bucket SSE-KMS"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # IMPORTANT: compact() removes null statement so KMS never sees invalid principal
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = compact([
      local.kms_root_statement,
      local.kms_vault_role_statement
    ])
  })

  tags = var.tags
}

resource "aws_kms_alias" "this" {
  name          = var.kms_key_alias != "" ? var.kms_key_alias : "alias/vault-auto-snapshots-${var.bucket_name}"
  target_key_id = aws_kms_key.this.key_id
}

############################################
# Default bucket encryption: SSE-KMS (CMK)
############################################
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

############################################
# Bucket policy:
# - Deny non-HTTPS
# - Enforce SSE-KMS + enforce THIS CMK
# - Allow Vault role when provided
############################################
locals {
  deny_insecure_transport = {
    Sid       = "DenyInsecureTransport"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    Condition = {
      Bool = { "aws:SecureTransport" = "false" }
    }
  }

  deny_unencrypted_put = {
    Sid       = "DenyUnEncryptedObjectUploads"
    Effect    = "Deny"
    Principal = "*"
    Action    = ["s3:PutObject"]
    Resource  = "${aws_s3_bucket.this.arn}/*"
    Condition = {
      StringNotEquals = {
        "s3:x-amz-server-side-encryption" = "aws:kms"
      }
    }
  }

  deny_wrong_kms_key = {
    Sid       = "DenyWrongKmsKey"
    Effect    = "Deny"
    Principal = "*"
    Action    = ["s3:PutObject"]
    Resource  = "${aws_s3_bucket.this.arn}/*"
    Condition = {
      StringNotEquals = {
        "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.this.arn
      }
    }
  }

  allow_vault_role_statements = var.vault_role_arn != "" ? [
    {
      Sid       = "AllowVaultRoleBucketAccess"
      Effect    = "Allow"
      Principal = { AWS = var.vault_role_arn }
      Action    = ["s3:ListBucket", "s3:GetBucketLocation"]
      Resource  = aws_s3_bucket.this.arn
    },
    {
      Sid       = "AllowVaultRoleObjectAccess"
      Effect    = "Allow"
      Principal = { AWS = var.vault_role_arn }
      Action = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListBucketMultipartUploads",
        "s3:ListMultipartUploadParts"
      ]
      Resource = "${aws_s3_bucket.this.arn}/*"
    }
  ] : []

  bucket_policy = {
    Version = "2012-10-17"
    Statement = concat(
      [
        local.deny_insecure_transport,
        local.deny_unencrypted_put,
        local.deny_wrong_kms_key
      ],
      local.allow_vault_role_statements
    )
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode(local.bucket_policy)

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.this]
}