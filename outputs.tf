output "lambda_function_name" {
  value = aws_lambda_function.this.function_name
}

output "bucket_name" {
  value = aws_s3_bucket.quarantine.bucket
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.integrity.name
}