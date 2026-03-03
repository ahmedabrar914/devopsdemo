# controlled_failover.py
import os
import json
import time
import boto3
import urllib3
from urllib3.util.retry import Retry

secrets = boto3.client("secretsmanager")

PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

# Per PDF note: after promotion, use Cluster A root token to login to Cluster B
PRIMARY_TOKEN = os.environ["VAULT_PRIMARY_TOKEN"]

# Batch token secret (your vault/dr/failover-handler-batch-token)
FAILOVER_TOKEN_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]
FAILOVER_TOKEN_JSON_KEY = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

# CA handling — you told there are TWO CAs
PRIMARY_CA_SECRET_ID = os.environ["VAULT_PRIMARY_CA_SECRET_ID"]
SECONDARY_CA_SECRET_ID = os.environ["VAULT_SECONDARY_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # e.g. ca_pem

POST_PROMOTE_SLEEP_SECONDS = int(os.environ.get("POST_PROMOTE_SLEEP_SECONDS", "8"))

PRIMARY_CA_PATH = "/tmp/vault-primary-ca.pem"
SECONDARY_CA_PATH = "/tmp/vault-secondary-ca.pem"


def _load_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def _load_ca_to_tmp(secret_id: str, out_path: str) -> str:
    secret_val = _load_secret_string(secret_id)
    if VAULT_CA_SECRET_JSON_KEY:
        obj = json.loads(secret_val)
        pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
    else:
        pem = secret_val

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception(f"CA PEM invalid/missing in secret: {secret_id}")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(pem)
    return out_path


def build_http(ca_file_path: str):
    retries = Retry(
        total=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    return urllib3.PoolManager(
        retries=retries,
        cert_reqs="CERT_REQUIRED",
        ca_certs=ca_file_path,
    )


def _parse_json(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    return json.loads(txt)


def vault_get(http, addr: str, token: str, path: str):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = http.request("GET", url, headers=headers, timeout=urllib3.Timeout(connect=5, read=20))
    return resp.status, _parse_json(resp)


def vault_post(http, addr: str, token: str, path: str, payload: dict | None = None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    body = json.dumps(payload or {}).encode("utf-8")
    resp = http.request("POST", url, headers=headers, body=body, timeout=urllib3.Timeout(connect=5, read=40))
    return resp.status, _parse_json(resp)


def require_ok(step: str, status: int, data: dict, ok=(200, 204)):
    if status in ok:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": data.get("errors"),
        "response": data
    }, default=str))


def dr_status(http, addr: str, token: str):
    st, data = vault_get(http, addr, token, "sys/replication/dr/status")
    return {"http": st, "data": data}


def health(http, addr: str):
    url = f"{addr.rstrip('/')}/v1/sys/health"
    resp = http.request("GET", url, timeout=urllib3.Timeout(connect=5, read=20))
    try:
        data = _parse_json(resp)
    except Exception:
        data = {"text": resp.data.decode("utf-8", errors="replace")}
    return resp.status, data


def _get_batch_token() -> str:
    raw = _load_secret_string(FAILOVER_TOKEN_SECRET_ID)
    raw = raw.strip()
    # secret is key/value -> json, so extract token by key
    obj = json.loads(raw)
    tok = obj.get(FAILOVER_TOKEN_JSON_KEY)
    if not tok:
        raise Exception(f"Batch token key '{FAILOVER_TOKEN_JSON_KEY}' not found in secret {FAILOVER_TOKEN_SECRET_ID}")
    return tok


def run_controlled_failover(event, context):
    """
    PDF p49–50:
      1) demote Cluster A
      2) promote Cluster B using dr_operation_token (batch token)
      3) verify Cluster B mode=primary
    """
    if event.get("dry_run"):
        return {"statusCode": 200, "message": "dry_run=true, not executing"}

    # Load BOTH CA
    _load_ca_to_tmp(PRIMARY_CA_SECRET_ID, PRIMARY_CA_PATH)
    _load_ca_to_tmp(SECONDARY_CA_SECRET_ID, SECONDARY_CA_PATH)

    http_a = build_http(PRIMARY_CA_PATH)
    http_b = build_http(SECONDARY_CA_PATH)

    if event.get("validate_only"):
        return {
            "statusCode": 200,
            "mode": "controlled_failover",
            "primary_health": health(http_a, PRIMARY_ADDR),
            "secondary_health": health(http_b, SECONDARY_ADDR),
            "primary_dr_status": dr_status(http_a, PRIMARY_ADDR, PRIMARY_TOKEN),
            "secondary_dr_status": dr_status(http_b, SECONDARY_ADDR, PRIMARY_TOKEN),
        }

    steps = {}

    # Step 1: Demote Cluster A (Primary)
    st1, d1 = vault_post(http_a, PRIMARY_ADDR, PRIMARY_TOKEN, "sys/replication/dr/primary/demote", payload={})
    require_ok("p49_step1_demote_cluster_a", st1, d1)
    steps["p49_step1_demote_cluster_a"] = {"http": st1, "response": d1}

    # Step 2: Promote DR (Cluster B) with dr_operation_token=batch token
    batch_token = _get_batch_token()
    st2, d2 = vault_post(
        http_b,
        SECONDARY_ADDR,
        PRIMARY_TOKEN,
        "sys/replication/dr/secondary/promote",
        payload={"dr_operation_token": batch_token},
    )
    require_ok("p49_step2_promote_cluster_b", st2, d2)
    steps["p49_step2_promote_cluster_b"] = {"http": st2, "response": d2}

    time.sleep(POST_PROMOTE_SLEEP_SECONDS)

    # Step 3: Verify B is primary
    verify = dr_status(http_b, SECONDARY_ADDR, PRIMARY_TOKEN)
    steps["p50_step3_verify_cluster_b"] = verify

    return {
        "statusCode": 200,
        "mode": "controlled_failover",
        "steps": steps,
        "expected": {"cluster_b_mode_should_be": "primary"},
    }