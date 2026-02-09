output "replica_bucket_name" {
  value = aws_s3_bucket.replica.bucket
}

output "replica_bucket_arn" {
  value = aws_s3_bucket.replica.arn
}

output "replica_kms_key_arn" {
  value = aws_kms_key.replica.arn
}