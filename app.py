import os
import re
import hashlib
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


s3 = boto3.client("s3")
ddb = boto3.client("dynamodb")

RELEASES_URL = "https://releases.hashicorp.com/vault/"

BUCKET_NAME = os.environ["BUCKET_NAME"]
QUARANTINE_PREFIX = os.environ.get("QUARANTINE_PREFIX", "vault")
INTEGRITY_TABLE = os.environ["INTEGRITY_TABLE"]

ARCH = os.environ.get("ARCH", "linux_amd64")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
OBJECT_LOCK_MODE = os.environ.get("OBJECT_LOCK_MODE", "GOVERNANCE")


def read_url_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def read_url_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=180) as response:
        return response.read()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_latest_ent_version() -> str:
    html = read_url_text(RELEASES_URL)

    versions = re.findall(
        r'href="/vault/([0-9]+\.[0-9]+\.[0-9]+\+ent)/"',
        html
    )

    if not versions:
        raise RuntimeError("No stable Vault +ent version found")

    versions = list(set(versions))

    versions.sort(
        key=lambda v: tuple(
            map(int, v.replace("+ent", "").split("."))
        )
    )

    return versions[-1]


def parse_expected_sha(sums_text: str, zip_name: str) -> str:
    for line in sums_text.splitlines():
        parts = line.strip().split()

        if len(parts) >= 2 and parts[-1] == zip_name:
            return parts[0].lower()

    raise RuntimeError(f"SHA256 checksum not found for {zip_name}")


def s3_object_exists(bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        if error_code in ["404", "NoSuchKey", "NotFound"]:
            return False

        if error_code == "403":
            print(
                f"WARNING: HeadObject access denied for s3://{bucket}/{key}. "
                "Treating as object not existing."
            )
            return False

        raise


def upload_locked_object(
    key: str,
    body: bytes,
    metadata: dict,
    tags: dict
):
    retain_until = datetime.now(timezone.utc) + timedelta(days=RETENTION_DAYS)

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=body,
        Metadata=metadata,
        Tagging=urllib.parse.urlencode(tags),
        ObjectLockMode=OBJECT_LOCK_MODE,
        ObjectLockRetainUntilDate=retain_until
    )


def put_integrity_record(
    artifact_key: str,
    version: str,
    artifact_name: str,
    sha256: str,
    source_url: str,
    status: str,
    retention_until: str
):
    ddb.put_item(
        TableName=INTEGRITY_TABLE,
        Item={
            "artifact_key": {"S": artifact_key},
            "version": {"S": version},
            "artifact_name": {"S": artifact_name},
            "sha256": {"S": sha256},
            "source_url": {"S": source_url},
            "status": {"S": status},
            "retention_until": {"S": retention_until},
            "created_at": {
                "S": datetime.now(timezone.utc).isoformat()
            }
        }
    )


def lambda_handler(event, context):
    latest_version = get_latest_ent_version()

    print(f"Latest Vault Enterprise version: {latest_version}")

    zip_name = f"vault_{latest_version}_{ARCH}.zip"
    sums_name = f"vault_{latest_version}_SHA256SUMS"

    release_base_url = f"{RELEASES_URL}{latest_version}/"

    zip_url = f"{release_base_url}{urllib.parse.quote(zip_name)}"
    sums_url = f"{release_base_url}{urllib.parse.quote(sums_name)}"

    zip_key = f"{QUARANTINE_PREFIX}/{latest_version}/{zip_name}"
    sums_key = f"{QUARANTINE_PREFIX}/{latest_version}/{sums_name}"

    if s3_object_exists(BUCKET_NAME, zip_key):
        return {
            "status": "skipped",
            "message": "Latest version already exists in quarantine bucket",
            "version": latest_version,
            "s3_key": zip_key
        }

    print(f"Downloading SHA256SUMS: {sums_url}")
    sums_text = read_url_text(sums_url)

    print(f"Downloading ZIP: {zip_url}")
    zip_bytes = read_url_bytes(zip_url)

    expected_sha = parse_expected_sha(sums_text, zip_name)
    actual_sha = sha256_bytes(zip_bytes)

    print(f"Expected SHA256: {expected_sha}")
    print(f"Actual SHA256:   {actual_sha}")

    if expected_sha != actual_sha:
        raise RuntimeError(
            f"Checksum mismatch. expected={expected_sha}, actual={actual_sha}"
        )

    print("Checksum matched. Uploading to quarantine bucket.")

    retention_until = (
        datetime.now(timezone.utc) + timedelta(days=RETENTION_DAYS)
    ).isoformat()

    upload_locked_object(
        key=zip_key,
        body=zip_bytes,
        metadata={
            "version": latest_version,
            "sha256": expected_sha,
            "source": zip_url
        },
        tags={
            "scan_status": "pending",
            "integrity": "verified",
            "artifact": "vault"
        }
    )

    upload_locked_object(
        key=sums_key,
        body=sums_text.encode("utf-8"),
        metadata={
            "version": latest_version,
            "source": sums_url
        },
        tags={
            "scan_status": "pending",
            "integrity": "verified",
            "artifact": "vault"
        }
    )

    put_integrity_record(
        artifact_key=zip_key,
        version=latest_version,
        artifact_name=zip_name,
        sha256=expected_sha,
        source_url=zip_url,
        status="verified_uploaded_locked",
        retention_until=retention_until
    )

    return {
        "status": "success",
        "version": latest_version,
        "zip_file": zip_name,
        "sha256_file": sums_name,
        "sha256": expected_sha,
        "zip_s3_key": zip_key,
        "sums_s3_key": sums_key,
        "object_lock_mode": OBJECT_LOCK_MODE,
        "retention_days": RETENTION_DAYS
    }