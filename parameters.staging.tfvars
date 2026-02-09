enable_replication = true

replica_region      = "us-east-1"
replica_bucket_name = "vault-snapshots-staging-us-east-1-<unique>"

replication_prefix = "vault/raft-snapshots/"

replica_object_lock_mode = "GOVERNANCE"
replica_object_lock_days = 30