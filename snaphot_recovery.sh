Below is a professional SOP that you can use in your team’s documentation (Confluence, SharePoint, GitLab Wiki, etc.). It follows a standard operations format with prerequisites, warnings, procedures, validation, and rollback considerations.

⸻

Standard Operating Procedure (SOP)

HashiCorp Vault Raft Snapshot Restore from Amazon S3

Document Information

Field	Value
SOP Name	HashiCorp Vault Snapshot Restore from S3
Environment	Vault Enterprise
Storage Backend	Integrated Storage (Raft)
Cloud Provider	AWS
Objective	Restore Vault cluster from a Raft snapshot stored in Amazon S3
Impact	High (Service affecting)
Downtime	Required during restore

⸻

1. Purpose

This SOP describes the process for restoring a HashiCorp Vault cluster using a Raft snapshot stored in Amazon S3.

The procedure restores the complete Vault storage state from a previously generated snapshot.

Warning

Restoring a snapshot completely overwrites the current Vault storage. Any data written after the snapshot was taken will be permanently lost.

⸻

2. Scope

This SOP applies to:

* Production Vault clusters
* Disaster Recovery
* Cluster Recovery
* Data Restoration
* Cross-region recovery using replicated S3 snapshots

⸻

3. Prerequisites

Before starting the restore process, ensure the following:

* Access to Bastion Host
* SSH access to Vault instances
* Vault Root Token (or token with sudo capability on sys/storage)
* AWS CLI installed and configured
* Snapshot available in S3
* Access to Vault TLS certificates
* Knowledge of current Vault Leader node

⸻

4. Required Information

Prepare the following information before beginning.

Parameter	Example
Vault DNS	vault.example.com
Vault Leader IP	xx.xx.xx.xx
S3 Bucket	vault-backup-bucket
Snapshot Name	vault-2026-07-05.snap
Root Token	********
CA Certificate	/etc/vault.d/tls/ca.pem

⸻

5. Pre-Restore Verification

Step 1 – Connect to Bastion Host

Login to the Bastion host that has access to the Vault cluster.

⸻

Step 2 – Connect to Any Vault Node

ssh -i "<pem-key>" ubuntu@<vault-instance-ip>

⸻

Step 3 – Configure Vault Environment

export VAULT_ADDR=https://<vault-dns>:8200
export VAULT_CACERT=/etc/vault.d/tls/ca.pem

⸻

Step 4 – Verify Vault Status

vault status

Confirm that:

* Vault is initialized
* Vault is unsealed
* Cluster is healthy

⸻

Step 5 – Identify the Leader Node

vault operator raft list-peers

Example:

Node        Address
vault-1     Leader
vault-2     Follower
vault-3     Follower

Identify the node marked as Leader.

⸻

Step 6 – Connect to the Leader Node

ssh -i "<pem-key>" ubuntu@<leader-node-ip>

⸻

Step 7 – Configure Vault Environment on Leader

export VAULT_ADDR=https://<vault-dns>:8200
export VAULT_CACERT=/etc/vault.d/tls/ca.pem
export VAULT_SKIP_VERIFY=true

⸻

Step 8 – Authenticate to Vault

vault login <token>

Verify successful authentication.

⸻

6. Restore Procedure from Primary S3 Bucket

Step 1 – (Optional) Stop Vault

If required, stop the Vault service.

sudo systemctl stop vault

Only perform this step if instructed during the recovery activity or if the restore cannot be completed while Vault is running.

⸻

Step 2 – Download Snapshot

Download directly from S3.

aws s3 cp s3://<bucket>/<folder>/<snapshot>.snap /tmp/vault.snap

Alternatively:

1. Open AWS Console.
2. Navigate to the S3 bucket.
3. Open the snapshot folder.
4. Copy the S3 URI.
5. Download using:

aws s3 cp <S3_URI> /tmp/vault.snap

⸻

Step 3 – Restore Snapshot

Restore using:

vault operator raft snapshot restore /tmp/vault.snap

If Vault refuses because existing data exists:

vault operator raft snapshot restore -force /tmp/vault.snap

⸻

Step 4 – Restart Vault (Only if stopped)

sudo systemctl start vault

Allow Vault several moments to initialize.

⸻

7. Restore Procedure from Cross-Region Replication Bucket

If the primary region is unavailable, restore using the replicated S3 bucket.

The procedure is identical except the snapshot is downloaded from the replication bucket.

⸻

Step 1 – Stop Vault

sudo systemctl stop vault

⸻

Step 2 – Download Snapshot

aws s3 cp s3://<replication-bucket>/<folder>/<snapshot>.snap /tmp/vault.snap

Or copy the S3 URI from the AWS Console and download.

⸻

Step 3 – Restore Snapshot

vault operator raft snapshot restore /tmp/vault.snap

⸻

Step 4 – Restart Vault

sudo systemctl start vault

⸻

8. Verify Cross-Region Replication Configuration

To verify S3 Cross-Region Replication (CRR):

1. Open AWS Console.
2. Navigate to the Primary S3 Bucket.
3. Select the Management tab.
4. Open Replication Rules.
5. Verify:

* Replication Rule is Enabled
* Destination Bucket is correct
* Destination Region matches DR Region

Snapshots uploaded to the Primary Bucket are automatically replicated to the configured Replication Bucket.

⸻

9. Post-Restore Validation

After restoration, perform the following checks.

Verify Vault Status

vault status

Expected:

* Initialized = true
* Sealed = false
* HA Enabled = true

⸻

Verify Leader

vault operator raft list-peers

Confirm:

* Leader is elected
* Followers are healthy

⸻

Verify Cluster Health

vault operator members

Ensure all expected cluster members are present.

⸻

Verify Secrets

Retrieve a known secret.

vault kv get <secret-path>

Confirm the restored data matches expectations.

⸻

Verify Authentication

Validate that authentication methods are functioning.

Examples:

* LDAP
* AppRole
* Kubernetes Auth
* AWS Auth

⸻

Verify Applications

Confirm dependent applications can:

* Authenticate to Vault
* Read secrets
* Renew leases
* Generate dynamic credentials

⸻

10. Failure Recovery

If the restore fails:

1. Verify the snapshot file is valid.
2. Ensure the snapshot matches the Vault version.
3. Verify the token has sudo capability on sys/storage.
4. Retry using:

vault operator raft snapshot restore -force /tmp/vault.snap

5. Review Vault logs:

journalctl -u vault -f

⸻

11. Important Notes

* Restore operations must always be executed on the Raft Leader.
* Restoring a snapshot permanently replaces the existing Vault storage.
* Any secrets created after the snapshot was taken will be lost.
* Verify the snapshot timestamp before restoring.
* Perform restores only during an approved maintenance window.
* Ensure all stakeholders are informed prior to initiating the restore.

⸻

12. References

* HashiCorp Vault Integrated Storage (Raft)
* Vault Snapshot Commands
* AWS S3 Cross-Region Replication (CRR)
* Internal Vault Backup and Recovery Runbook

⸻

This SOP is structured in the format typically expected by enterprise operations teams, with clear sections for purpose, prerequisites, procedures, validation, and operational notes. It is suitable for inclusion in Confluence, GitLab Wiki, or internal documentation.