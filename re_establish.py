# re_establish_dr.py
import os
import json
import time
import boto3
import urllib3
from urllib3.util.retry import Retry

secrets = boto3.client("secretsmanager")

PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]      # Cluster A
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]  # Cluster B

PRIMARY_TOKEN = os.environ["VAULT_PRIMARY_TOKEN"]

# IMPORTANT: PDF Step-2 uses id=<cluster-b-region> (Cluster B ID)
SECONDARY_CLUSTER_ID = os.environ["VAULT_SECONDARY_CLUSTER_ID"]

FAILOVER_TOKEN_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]
FAILOVER_TOKEN_JSON_KEY = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

PRIMARY_CA_SECRET_ID = os.environ["VAULT_PRIMARY_CA_SECRET_ID"]
SECONDARY_CA_SECRET_ID = os.environ["VAULT_SECONDARY_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")

POST_UPDATE_SLEEP_SECONDS = int(os.environ.get("POST_UPDATE_SLEEP_SECONDS", "6"))

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


def _get_batch_token() -> str:
    raw = _load_secret_string(FAILOVER_TOKEN_SECRET_ID).strip()
    obj = json.loads(raw)
    tok = obj.get(FAILOVER_TOKEN_JSON_KEY)
    if not tok:
        raise Exception(f"Batch token key '{FAILOVER_TOKEN_JSON_KEY}' not found in secret {FAILOVER_TOKEN_SECRET_ID}")
    return tok


def run_re_establish_dr(event, context):
    """
    PDF p51–52:
      PRE: demote Cluster A
      1) generate-public-key on A
      2) secondary-token on B (id = cluster-b-region)
      3) update-primary on A (batch token + activation token)
      4) verify dr status on both
    """
    if event.get("dry_run"):
        return {"statusCode": 200, "message": "dry_run=true, not executing"}

    _load_ca_to_tmp(PRIMARY_CA_SECRET_ID, PRIMARY_CA_PATH)
    _load_ca_to_tmp(SECONDARY_CA_SECRET_ID, SECONDARY_CA_PATH)

    http_a = build_http(PRIMARY_CA_PATH)
    http_b = build_http(SECONDARY_CA_PATH)

    if event.get("validate_only"):
        return {
            "statusCode": 200,
            "mode": "re_establish_dr",
            "cluster_a_dr_status": dr_status(http_a, PRIMARY_ADDR, PRIMARY_TOKEN),
            "cluster_b_dr_status": dr_status(http_b, SECONDARY_ADDR, PRIMARY_TOKEN),
        }

    steps = {}

    # PRE STEP (must run before generate-public-key) — you highlighted this
    st0, d0 = vault_post(http_a, PRIMARY_ADDR, PRIMARY_TOKEN, "sys/replication/dr/primary/demote", payload={})
    require_ok("p51_pre_demote_cluster_a", st0, d0)
    steps["p51_pre_demote_cluster_a"] = {"http": st0, "response": d0}

    # Step 1: Get Public Key (on Cluster A)
    st1, d1 = vault_post(http_a, PRIMARY_ADDR, PRIMARY_TOKEN, "sys/replication/dr/secondary/generate-public-key", payload={})
    require_ok("p51_step1_generate_public_key", st1, d1)

    pub = (d1.get("data") or {}).get("secondary_public_key")
    if not pub:
        raise Exception(json.dumps({"step": "p51_step1_generate_public_key", "error": "secondary_public_key missing", "response": d1}))
    steps["p51_step1_generate_public_key"] = {"http": st1, "secondary_public_key_prefix": pub[:12] + "..."}

    # Step 2: Generate Activation Token (on Cluster B)
    st2, d2 = vault_post(
        http_b,
        SECONDARY_ADDR,
        PRIMARY_TOKEN,
        "sys/replication/dr/primary/secondary-token",
        payload={"secondary_public_key": pub, "id": SECONDARY_CLUSTER_ID},
    )
    require_ok("p52_step2_generate_activation_token", st2, d2)

    activation = (d2.get("data") or {}).get("token")
    if not activation:
        raise Exception(json.dumps({"step": "p52_step2_generate_activation_token", "error": "token missing", "response": d2}))
    steps["p52_step2_generate_activation_token"] = {"http": st2, "activation_token_prefix": activation[:12] + "..."}

    # Step 3: Update Cluster A to Secondary Status (on Cluster A)
    batch_token = _get_batch_token()
    st3, d3 = vault_post(
        http_a,
        PRIMARY_ADDR,
        PRIMARY_TOKEN,
        "sys/replication/dr/secondary/update-primary",
        payload={"dr_operation_token": batch_token, "token": activation},
    )
    require_ok("p52_step3_update_primary", st3, d3)
    steps["p52_step3_update_primary"] = {"http": st3, "response": d3}

    time.sleep(POST_UPDATE_SLEEP_SECONDS)

    # Step 4: Verify Replication Status (both clusters)
    steps["p52_step4_verify_a"] = dr_status(http_a, PRIMARY_ADDR, PRIMARY_TOKEN)
    steps["p52_step4_verify_b"] = dr_status(http_b, SECONDARY_ADDR, PRIMARY_TOKEN)

    return {
        "statusCode": 200,
        "mode": "re_establish_dr",
        "steps": steps,
        "expected": {"cluster_b_mode_should_be": "primary", "cluster_a_mode_should_be": "secondary"},
    }