data "aws_caller_identity" "current" {}

# ----------------------------------------------------------
# Replica bucket in DR region (aws.dr)
# ----------------------------------------------------------
resource "aws_s3_bucket" "replica" {
  provider = aws.dr
  bucket   = var.replica_bucket_name

  # Must be true at creation time
  object_lock_enabled = true

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id

  rule {
    default_retention {
      mode = var.replica_object_lock_mode
      days = var.replica_object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.replica]
}

# ----------------------------------------------------------
# Replica KMS key (DR region)
# ----------------------------------------------------------
resource "aws_kms_key" "replica" {
  provider                = aws.dr
  description             = "CMK for Vault snapshot replica bucket SSE-KMS"
  enable_key_rotation     = true
  deletion_window_in_days = 30

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

resource "aws_kms_alias" "replica" {
  provider      = aws.dr
  name          = "alias/vault-snapshots-replica"
  target_key_id = aws_kms_key.replica.key_id
}

# ----------------------------------------------------------
# IAM Role for S3 replication (primary region)
# ----------------------------------------------------------
resource "aws_iam_role" "replication" {
  name = "vault-snapshots-s3-replication-staging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "replication" {
  name = "vault-snapshots-s3-replication-policy-staging"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Read from source
      {
        Sid    = "ReadFromSourceBucket"
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
          "s3:GetBucketVersioning"
        ]
        Resource = [var.source_bucket_arn]
      },
      {
        Sid    = "ReadSourceObjectVersions"
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
          "s3:GetObjectRetention",
          "s3:GetObjectLegalHold"
        ]
        Resource = ["${var.source_bucket_arn}/${var.replication_prefix}*"]
      },

      # Write to destination
      {
        Sid    = "ReplicateToDestination"
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:ObjectOwnerOverrideToBucketOwner",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
          "s3:PutObjectTagging"
        ]
        Resource = ["${aws_s3_bucket.replica.arn}/${var.replication_prefix}*"]
      },

      # KMS for replication
      {
        Sid    = "KMSForReplication"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          var.source_kms_key_arn,
          aws_kms_key.replica.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

# ----------------------------------------------------------
# Enable replication on the SOURCE bucket (primary)
# ----------------------------------------------------------
resource "aws_s3_bucket_replication_configuration" "this" {
  bucket = var.source_bucket_name
  role   = aws_iam_role.replication.arn

  rule {
    id     = "vault-snapshots-crr-staging"
    status = "Enabled"

    filter {
      prefix = var.replication_prefix
    }

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica.arn
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.replica
  ]
}