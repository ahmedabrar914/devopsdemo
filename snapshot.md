---
title: "SOP: Vault Snapshot Restore"
---

# SOP: Vault Snapshot Restore

## Purpose

This SOP describes the process for restoring a HashiCorp Vault cluster from a Raft snapshot stored in Amazon S3. It applies to both the primary backup bucket and the cross-region replicated backup bucket.

> **Warning**
>
> Restoring a snapshot completely replaces the current Vault storage. Any data written after the snapshot was taken will be permanently lost.

---

# When to Restore

A snapshot restore should only be performed during approved maintenance windows or disaster recovery scenarios such as:

- Vault data corruption
- Accidental deletion of secrets
- Failed upgrade requiring rollback
- Disaster Recovery (DR)
- Cluster rebuild after infrastructure failure

---

# Impact Assessment

Before proceeding, understand the impact.

- Existing Vault data will be overwritten.
- Secrets written after the snapshot timestamp will be lost.
- Vault will be unavailable during the restore.
- Applications depending on Vault may experience authentication failures until the cluster is restored.

Record:

| Item | Value |
|------|-------|
| Snapshot Timestamp | |
| Expected Data Loss Window | |
| Maintenance Window | |
| Change Request | |

---

# Pre-Restore Checklist

Verify the following before beginning.

- [ ] Approved maintenance window
- [ ] Stakeholders notified
- [ ] Valid snapshot identified
- [ ] Root token or token with sudo capability available
- [ ] Bastion access confirmed
- [ ] SSH access to Vault nodes
- [ ] AWS CLI configured
- [ ] Vault Leader identified
- [ ] Snapshot integrity verified

---

# Locate the Snapshot

Snapshots are stored in Amazon S3.

Primary Bucket

```
s3://<bucket>/<snapshot-folder>/
```

or

Navigate to

AWS Console → S3 → Bucket → Objects → Snapshot Folder

Copy the snapshot S3 URI.

For Disaster Recovery, snapshots can also be restored from the Cross-Region Replication bucket.

---

# Snapshot Inspection

Before restoring, inspect the snapshot metadata.

```bash
vault operator raft snapshot inspect /tmp/vault.snap
```

Verify:

- Snapshot ID
- Snapshot Size
- Snapshot Timestamp
- Raft Version

Ensure the snapshot is the expected backup before continuing.

---

# Restore Procedure

## Step 1 - Connect to Bastion

Login to the Bastion host.

---

## Step 2 - SSH to a Vault Node

```bash
ssh -i "<pem-key>" ubuntu@<vault-node-ip>
```

---

## Step 3 - Configure Vault Environment

```bash
export VAULT_ADDR=https://<vault-dns>:8200
export VAULT_CACERT=/etc/vault.d/tls/ca.pem
```

---

## Step 4 - Verify Vault Status

```bash
vault status
```

---

## Step 5 - Identify the Leader

```bash
vault operator raft list-peers
```

---

## Step 6 - SSH to the Leader

```bash
ssh -i "<pem-key>" ubuntu@<leader-ip>
```

---

## Step 7 - Configure Vault

```bash
export VAULT_ADDR=https://<vault-dns>:8200
export VAULT_CACERT=/etc/vault.d/tls/ca.pem
export VAULT_SKIP_VERIFY=true
```

---

## Step 8 - Login

```bash
vault login <token>
```

---

## Step 9 - Stop Vault (Optional)

If required,

```bash
sudo systemctl stop vault
```

---

## Step 10 - Download Snapshot

Primary Bucket

```bash
aws s3 cp s3://<bucket>/<folder>/<snapshot>.snap /tmp/vault.snap
```

or

```bash
aws s3 cp <S3_URI> /tmp/vault.snap
```

---

## Step 11 - Restore Snapshot

```bash
vault operator raft snapshot restore /tmp/vault.snap
```

If Vault refuses because existing data exists,

```bash
vault operator raft snapshot restore -force /tmp/vault.snap
```

---

## Step 12 - Restart Vault (If Stopped)

```bash
sudo systemctl start vault
```

---

# Cross Region Restore

If the primary region is unavailable,

Download the snapshot from the Cross-Region Replication bucket.

```bash
aws s3 cp s3://<replication-bucket>/<folder>/<snapshot>.snap /tmp/vault.snap
```

Then perform the same restore procedure described above.

---

# Post-Restore Validation

After the restore completes, perform the following checks.

## Verify Vault Status

```bash
vault status
```

Expected:

- Initialized = true
- Sealed = false
- HA Enabled = true

---

## Verify Leader Election

```bash
vault operator raft list-peers
```

Ensure one node is Leader and the remaining nodes are Followers.

---

## Verify Cluster Members

```bash
vault operator members
```

Confirm all expected nodes are healthy.

---

## Verify Secrets

Retrieve a known secret.

```bash
vault kv get <secret-path>
```

---

## Verify Authentication

Validate authentication methods such as:

- AppRole
- Kubernetes Auth
- LDAP
- AWS Auth

---

## Verify Applications

Confirm applications can:

- Authenticate successfully
- Read secrets
- Renew leases
- Access dynamic credentials

---

# Stakeholder Communication

## Before Restore

Notify:

- Application Owners
- Platform Team
- Security Team
- Change Management

Example:

> Vault snapshot restoration will begin at **HH:MM UTC**. Vault services will be unavailable during the maintenance window.

---

## After Restore

Notify:

> Vault snapshot restoration has completed successfully. Cluster health and application connectivity have been validated.

---

# Failure Recovery

If restore fails,

1. Verify snapshot integrity.
2. Confirm Vault version compatibility.
3. Verify token permissions.
4. Retry using

```bash
vault operator raft snapshot restore -force /tmp/vault.snap
```

5. Review Vault logs

```bash
journalctl -u vault -f
```

---

# References

- HashiCorp Vault Integrated Storage Snapshots
- HashiCorp Vault Disaster Recovery Documentation
- AWS S3 Cross Region Replication Documentation