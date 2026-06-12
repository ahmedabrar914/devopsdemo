data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_src/vault_release_downloader.py"
  output_path = "${path.module}/lambda_src/vault_release_downloader.zip"
}

locals {
  approved_bucket_name         = coalesce(var.approved_bucket_name, "${var.bucket_name}-approved")
  rl_scanner_input_bucket_name = split("/", trimprefix(var.rl_scanner_input_s3_location, "s3://"))[0]
}

resource "aws_s3_bucket" "quarantine" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket" "approved_artifact" {
  bucket = local.approved_bucket_name
}

resource "aws_s3_bucket_policy" "deny_delete" {
  bucket = aws_s3_bucket.approved_artifact.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyObjectDeleteForEveryone"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.approved_artifact.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_dynamodb_table" "integrity" {
  name         = var.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "artifact_key"

  attribute {
    name = "artifact_key"
    type = "S"
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.lambda_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name = "${var.lambda_name}-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:PutObjectTagging",
          "s3:PutObjectRetention"
        ]
        Resource = [
          aws_s3_bucket.quarantine.arn,
          "${aws_s3_bucket.quarantine.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.integrity.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

resource "aws_lambda_function" "this" {
  function_name = var.lambda_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "vault_release_downloader.lambda_handler"
  runtime       = var.runtime

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = var.timeout
  memory_size = var.memory_size

  environment {
    variables = {
      BUCKET_NAME       = aws_s3_bucket.quarantine.bucket
      QUARANTINE_PREFIX = var.quarantine_prefix
      INTEGRITY_TABLE   = aws_dynamodb_table.integrity.name
      ARCH              = var.arch
      RETENTION_DAYS    = tostring(var.retention_days)
      OBJECT_LOCK_MODE  = var.object_lock_mode
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy_attach
  ]
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.lambda_name}-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "${var.lambda_name}-target"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}



############################################
# CloudWatch Log Groups
############################################
resource "aws_cloudwatch_log_group" "dispatch" {
  name              = "/aws/lambda/${var.rl_name_prefix}-dispatch"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "promoter" {
  name              = "/aws/lambda/${var.rl_name_prefix}-promoter"
  retention_in_days = 30
}

############################################
# IAM ROLE 1: Dispatch Lambda role + policy
############################################
resource "aws_iam_role" "dispatch_role" {
  name = "${var.rl_name_prefix}-dispatch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "LambdaAssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "dispatch_policy" {
  name = "${var.rl_name_prefix}-dispatch-policy"
  role = aws_iam_role.dispatch_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteDispatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.dispatch.arn}:*"
      },
      {
        Sid      = "SendScanJobs"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.scan_jobs.arn
      }
    ]
  })
}

############################################
# IAM ROLE 2: Promoter Lambda role + policy
############################################
resource "aws_iam_role" "promoter_role" {
  name = "${var.rl_name_prefix}-promoter-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "LambdaAssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "promoter_policy" {
  name = "${var.rl_name_prefix}-promoter-policy"
  role = aws_iam_role.promoter_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WritePromoterLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.promoter.arn}:*"
      },
      {
        Sid      = "ConsumeScanResults"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.scan_results.arn
      },
      {
        Sid    = "S3ReadTagCopyDeleteSource"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectTagging",
          "s3:PutObjectTagging",
          "s3:PutObject",
          "s3:PutObjectTagging",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.quarantine.arn}/*",
          "${aws_s3_bucket.approved_artifact.arn}/*"
        ]
      },
      {
        Sid    = "S3ListBucketsForTaggingChecks"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.quarantine.arn,
          aws_s3_bucket.approved_artifact.arn
        ]
      }
    ]
  })
}

############################################
# IAM ROLE 3: EC2 worker role + policy + profile
############################################
resource "aws_iam_role" "worker_role" {
  name = "${var.rl_name_prefix}-worker-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EC2AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "worker_policy" {
  name = "${var.rl_name_prefix}-worker-policy"
  role = aws_iam_role.worker_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PollJobsAndPublishResults"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sqs_queue.scan_jobs.arn,
          aws_sqs_queue.scan_results.arn
        ]
      },
      {
        Sid      = "ReadArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.quarantine.arn}/*"
      },
      {
        Sid    = "RlStaticBucketRead"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.rl_static_artifacts_bucket_name}",
          "arn:aws:s3:::${var.rl_static_artifacts_bucket_name}/*"
        ]
      },
      {
        Sid    = "RlScannerBucketReadWrite"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${local.rl_scanner_input_bucket_name}",
          "arn:aws:s3:::${local.rl_scanner_input_bucket_name}/*"
        ]
      },
      {
        Sid    = "ReadRlSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          var.rl_license_secret_arn,
          var.rl_site_key_secret_arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "worker_profile" {
  name = "${var.rl_name_prefix}-worker-profile"
  role = aws_iam_role.worker_role.name
}

resource "aws_iam_role_policy_attachment" "worker_ssm_core" {
  role       = aws_iam_role.worker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
