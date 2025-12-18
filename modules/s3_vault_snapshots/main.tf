############################################
# S3 bucket for Vault auto-snapshots (private)
############################################

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  tags   = var.tags
}

# Block ALL public access (private bucket baseline)
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Disable ACLs entirely (recommended modern posture)
resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning is recommended for backup/snapshots
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

############################################
# Bucket policy
# - Always deny non-HTTPS
# - Optionally allow Vault role (when vault_role_arn is set)
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
      Bool = {
        "aws:SecureTransport" = "false"
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
    Version   = "2012-10-17"
    Statement = concat(
      [local.deny_insecure_transport],
      local.allow_vault_role_statements
    )
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode(local.bucket_policy)
}