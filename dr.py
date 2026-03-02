import os
import json
import boto3
import urllib3
from urllib3.util.retry import Retry

# ----------------------------
# Required env vars
# ----------------------------
USW2_ADDR = os.environ["VAULT_USW2_ADDR"]       # https://usw2.dev.vault.corp.zscaler.com:8200
USE1_ADDR = os.environ["VAULT_USE1_ADDR"]       # https://use1.dev.vault.corp.zscaler.com:8200
USW2_TOKEN = os.environ["VAULT_USW2_TOKEN"]
USE1_TOKEN = os.environ["VAULT_USE1_TOKEN"]

# CA from Secrets Manager
VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]  # name or ARN
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # e.g. "ca_pem" if secret is JSON

# Cache file path in Lambda writable dir
CA_PATH = "/tmp/vault-ca.pem"

secrets = boto3.client("secretsmanager")


def load_ca_to_tmp() -> str:
    """
    Fetch CA PEM from Secrets Manager and write to /tmp/vault-ca.pem.
    Returns the CA file path.
    """
    resp = secrets.get_secret_value(SecretId=VAULT_CA_SECRET_ID)

    # SecretString is most common; SecretBinary is possible
    if "SecretString" in resp and resp["SecretString"]:
        secret_val = resp["SecretString"]
    else:
        # If SecretBinary, decode bytes
        secret_val = resp["SecretBinary"].decode("utf-8")

    pem = None

    # If JSON secret and key provided
    if VAULT_CA_SECRET_JSON_KEY:
        try:
            obj = json.loads(secret_val)
            pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
        except json.JSONDecodeError:
            raise Exception("VAULT_CA_SECRET_JSON_KEY set but secret is not valid JSON")
    else:
        # Treat secret as plain PEM string
        pem = secret_val

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception("CA PEM not found or invalid in Secrets Manager secret")

    # Write to /tmp
    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(pem)

    return CA_PATH


def build_http(ca_file_path: str):
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    return urllib3.PoolManager(
        retries=retries,
        cert_reqs="CERT_REQUIRED",
        ca_certs=ca_file_path,
    )


def vault_get(http: urllib3.PoolManager, addr: str, token: str, path: str):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = http.request(
        "GET",
        url,
        headers=headers,
        timeout=urllib3.Timeout(connect=5, read=15),
    )
    body = resp.data.decode("utf-8", errors="replace").strip() if resp.data else ""
    data = json.loads(body) if body else {}
    return resp.status, data


def summarize_health(status_code: int, health_json: dict):
    return {
        "http": status_code,
        "initialized": health_json.get("initialized"),
        "sealed": health_json.get("sealed"),
        "standby": health_json.get("standby"),
        "version": health_json.get("version"),
        "cluster_name": health_json.get("cluster_name"),
        "cluster_id": health_json.get("cluster_id"),
    }


def summarize_leader(status_code: int, leader_json: dict):
    data = leader_json.get("data") or leader_json
    return {
        "http": status_code,
        "ha_enabled": data.get("ha_enabled"),
        "is_self": data.get("is_self"),
        "leader_address": data.get("leader_address"),
        "leader_cluster_address": data.get("leader_cluster_address"),
    }


def check_cluster(http: urllib3.PoolManager, name: str, addr: str, token: str):
    h_st, h_json = vault_get(http, addr, token, "sys/health")
    l_st, l_json = vault_get(http, addr, token, "sys/leader")

    standby = h_json.get("standby")
    sealed = h_json.get("sealed")
    if sealed is True:
        role = "sealed"
    elif standby is True:
        role = "standby"
    elif standby is False:
        role = "active"
    else:
        role = "unknown"

    return {
        "cluster": name,
        "addr": addr,
        "role": role,
        "health": summarize_health(h_st, h_json),
        "leader": summarize_leader(l_st, l_json),
    }


def lambda_handler(event, context):
    ca_file = load_ca_to_tmp()
    http = build_http(ca_file)

    results = {
        "usw2": check_cluster(http, "usw2", USW2_ADDR, USW2_TOKEN),
        "use1": check_cluster(http, "use1", USE1_ADDR, USE1_TOKEN),
    }

    return {"statusCode": 200, "body": json.dumps(results, default=str)}