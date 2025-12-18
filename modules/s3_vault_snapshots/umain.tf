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
# KMS CMK for SSE-KMS (customer-managed)
############################################
resource "aws_kms_key" "this" {
  description             = "CMK for Vault auto-snapshots bucket SSE-KMS"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Minimal key policy: allow account root full admin.
  # (If your org uses an admin role, swap root for that role.)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnableRootPermissions"
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

data "aws_caller_identity" "current" {}

resource "aws_kms_alias" "this" {
  name          = var.kms_key_alias != "" ? var.kms_key_alias : "alias/vault-auto-snapshots-${var.bucket_name}"
  target_key_id = aws_kms_key.this.key_id
}

############################################
# S3 default encryption: SSE-KMS using CMK
############################################
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }

    # Optional but recommended: reduces KMS calls/cost
    bucket_key_enabled = true
  }
}

############################################
# Bucket policy
# - Deny non-HTTPS
# - Deny PUT without SSE-KMS + enforce our CMK
# - Optional: allow Vault role (when provided)
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

  # Enforce SSE-KMS on object uploads
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

  # Enforce the specific CMK (prevents someone using aws managed key or another CMK)
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

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.this
  ]
}