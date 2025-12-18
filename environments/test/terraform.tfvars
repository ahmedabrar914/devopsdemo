region               = "us-east-1"
name_prefix          = "vaas"
env                  = "test"

# must be globally unique
snapshot_bucket_name = "vault-auto-snapshots-vaas-test-12345"

# replace with your real vault role ARN (EC2 role or IRSA role)
vault_role_arn       = "arn:aws:iam::123456789012:role/vault-snapshot-writer"

tags = {
  Owner = "platform"
}