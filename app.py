import boto3
import re
import urllib.request
from packaging.version import Version

BUCKET_NAME = "your-s3-bucket-name"
PREFIX = "hashicorp/vault"
RELEASE_URL = "https://releases.hashicorp.com/vault/"

s3 = boto3.client("s3")


def get_url_content(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def download_binary(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def get_latest_ent_version():
    html = get_url_content(RELEASE_URL)

    pattern = r'vault_(\d+\.\d+\.\d+)\+ent/'
    versions = re.findall(pattern, html)

    if not versions:
        raise Exception("No Vault Enterprise versions found")

    latest = sorted(set(versions), key=Version, reverse=True)[0]
    return latest


def get_last_downloaded_version():
    key = f"{PREFIX}/last_version.txt"

    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        return obj["Body"].read().decode("utf-8").strip()
    except s3.exceptions.NoSuchKey:
        return None
    except Exception:
        return None


def save_last_downloaded_version(version):
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=f"{PREFIX}/last_version.txt",
        Body=version.encode("utf-8")
    )


def upload_file_to_s3(filename, content, version):
    key = f"{PREFIX}/{version}/{filename}"

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=content
    )

    print(f"Uploaded s3://{BUCKET_NAME}/{key}")


def lambda_handler(event, context):
    latest_version = get_latest_ent_version()
    last_version = get_last_downloaded_version()

    print(f"Latest Vault Enterprise version: {latest_version}")
    print(f"Last downloaded version: {last_version}")

    if latest_version == last_version:
        return {
            "status": "skipped",
            "message": "No new Vault Enterprise version found",
            "version": latest_version
        }

    base_name = f"vault_{latest_version}+ent"
    version_url = f"{RELEASE_URL}{base_name}/"

    files_to_download = [
        f"{base_name}_SHA256SUMS",
        f"{base_name}_linux_amd64.zip"
    ]

    for filename in files_to_download:
        file_url = f"{version_url}{filename}"
        print(f"Downloading {file_url}")

        content = download_binary(file_url)
        upload_file_to_s3(filename, content, latest_version)

    save_last_downloaded_version(latest_version)

    return {
        "status": "success",
        "message": "New Vault Enterprise binaries uploaded",
        "version": latest_version,
        "files": files_to_download
    }