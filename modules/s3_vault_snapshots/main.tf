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

  allow_vault_role = var.vault_role_arn != "" ? [
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
    Statement = concat([local.deny_insecure_transport], local.allow_vault_role)
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode(local.bucket_policy)
}