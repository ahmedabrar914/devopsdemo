import os
import json
import time
import boto3
import urllib3
from urllib3.util.retry import Retry

# ----------------------------
# ENV VARS (required)
# ----------------------------
CLUSTER_A_ADDR = os.environ["VAULT_CLUSTER_A_ADDR"]   # old primary (ex: https://usw2...:8200)
CLUSTER_B_ADDR = os.environ["VAULT_CLUSTER_B_ADDR"]   # DR (ex: https://use1...:8200)

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]                 # CA PEM secret name/arn
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY") # optional, e.g. "ca_pem"

VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]                 # root token secret
VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token")      # if secret is JSON

VAULT_DR_BATCH_TOKEN_SECRET_ID = os.environ["VAULT_DR_BATCH_TOKEN_SECRET_ID"]         # dr batch token secret
VAULT_DR_BATCH_TOKEN_JSON_KEY = os.environ.get("VAULT_DR_BATCH_TOKEN_JSON_KEY", "token")

# When Cluster A becomes secondary again, Vault wants an id for the secondary in "secondary-token"
# In your PDF it shows: id='<cluster-b-region>' (that’s just an identifier). Use something stable like "usw2".
NEW_SECONDARY_ID = os.environ.get("VAULT_NEW_SECONDARY_ID", "cluster-a")

# Optional knobs
POST_DEMOTE_SLEEP_SECONDS = int(os.environ.get("POST_DEMOTE_SLEEP_SECONDS", "5"))
POST_PROMOTE_SLEEP_SECONDS = int(os.environ.get("POST_PROMOTE_SLEEP_SECONDS", "8"))

CA_PATH = "/tmp/vault-ca.pem"

secrets = boto3.client("secretsmanager")


# ----------------------------
# Secrets helpers
# ----------------------------
def _get_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if resp.get("SecretString"):
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def load_ca_to_tmp() -> str:
    raw = _get_secret_string(VAULT_CA_SECRET_ID)

    if VAULT_CA_SECRET_JSON_KEY:
        obj = json.loads(raw)
        pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
    else:
        pem = raw

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception("Invalid CA PEM from Secrets Manager")

    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(pem)

    return CA_PATH


def read_token_from_secret(secret_id: str, json_key: str = "token") -> str:
    raw = _get_secret_string(secret_id).strip()
    # If stored as JSON, read key; else treat as plaintext token
    if raw.startswith("{"):
        obj = json.loads(raw)
        token = obj.get(json_key)
    else:
        token = raw
    if not token:
        raise Exception(f"Token not found in secret: {secret_id}")
    return token.strip()


# ----------------------------
# HTTP (urllib3)
# ----------------------------
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
    resp = http.request("GET", url, headers=headers, timeout=urllib3.Timeout(connect=5, read=30))
    return resp.status, _parse_json(resp)


def vault_post(http, addr: str, token: str, path: str, payload: dict | None = None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    body = json.dumps(payload or {}).encode("utf-8")
    resp = http.request("POST", url, headers=headers, body=body, timeout=urllib3.Timeout(connect=5, read=60))
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


# ----------------------------
# DR status (try dr/status first; fallback to replication/status)
# ----------------------------
def get_dr_status(http, addr: str, token: str) -> dict:
    st, data = vault_get(http, addr, token, "sys/replication/dr/status")
    if st == 200 and isinstance(data, dict):
        d = data.get("data") or {}
        return {
            "http": st,
            "mode": d.get("mode"),
            "state": d.get("state"),
            "cluster_id": d.get("cluster_id"),
            "primary_cluster_addr": d.get("primary_cluster_addr"),
            "known_secondaries": d.get("known_secondaries"),
        }

    # fallback
    st2, data2 = vault_get(http, addr, token, "sys/replication/status")
    d2 = (data2.get("data") or {}).get("dr") or {}
    return {
        "http": st2,
        "mode": d2.get("mode"),
        "state": d2.get("state"),
        "cluster_id": d2.get("cluster_id"),
        "primary_cluster_addr": d2.get("primary_cluster_addr"),
        "known_secondaries": d2.get("known_secondaries"),
    }


# ----------------------------
# Controlled failover steps (per your PDF screenshots)
# ----------------------------
def demote_cluster_a_primary(http, root_token_a: str):
    # vault write -f sys/replication/dr/primary/demote
    st, data = vault_post(http, CLUSTER_A_ADDR, root_token_a, "sys/replication/dr/primary/demote", payload={})
    require_ok("demote_cluster_a_primary", st, data, ok=(200, 204))
    time.sleep(POST_DEMOTE_SLEEP_SECONDS)
    return st


def promote_cluster_b_dr(http, root_token_b: str, dr_batch_token: str):
    # vault write -force sys/replication/dr/secondary/promote dr_operation_token=<BATCH>
    payload = {"dr_operation_token": dr_batch_token}
    st, data = vault_post(http, CLUSTER_B_ADDR, root_token_b, "sys/replication/dr/secondary/promote", payload=payload)
    require_ok("promote_cluster_b_dr", st, data, ok=(200, 204))
    time.sleep(POST_PROMOTE_SLEEP_SECONDS)
    return st


def make_cluster_a_secondary_again(http, root_token_a: str, root_token_b: str, dr_batch_token: str):
    """
    After Cluster B becomes primary, configure Cluster A as DR secondary:

    On Cluster A:
      1) generate-public-key  -> secondary_public_key

    On Cluster B (new primary):
      2) primary/secondary-token secondary_public_key=<...> id=<cluster-a-id> -> activation token

    On Cluster A:
      3) secondary/update-primary dr_operation_token=<BATCH> token=<activation-token>
    """
    # Step 1 (on Cluster A): generate-public-key
    st1, data1 = vault_post(http, CLUSTER_A_ADDR, root_token_a, "sys/replication/dr/secondary/generate-public-key", payload={})
    require_ok("cluster_a_generate_public_key", st1, data1, ok=(200, 204))
    sec_pub = (data1.get("data") or {}).get("secondary_public_key")
    if not sec_pub:
        raise Exception(json.dumps({"step": "cluster_a_generate_public_key", "error": "secondary_public_key missing", "response": data1}))

    # Step 2 (on Cluster B): generate activation token for Cluster A
    payload2 = {"secondary_public_key": sec_pub, "id": NEW_SECONDARY_ID}
    st2, data2 = vault_post(http, CLUSTER_B_ADDR, root_token_b, "sys/replication/dr/primary/secondary-token", payload=payload2)
    require_ok("cluster_b_secondary_token", st2, data2, ok=(200, 204))
    activation = (data2.get("data") or {}).get("token")
    if not activation:
        raise Exception(json.dumps({"step": "cluster_b_secondary_token", "error": "token missing", "response": data2}))

    # Step 3 (on Cluster A): update-primary (uses DR batch token + activation token)
    payload3 = {"dr_operation_token": dr_batch_token, "token": activation}
    st3, data3 = vault_post(http, CLUSTER_A_ADDR, root_token_a, "sys/replication/dr/secondary/update-primary", payload=payload3)
    require_ok("cluster_a_update_primary", st3, data3, ok=(200, 204))

    return {
        "cluster_a_generate_public_key_http": st1,
        "cluster_b_secondary_token_http": st2,
        "cluster_a_update_primary_http": st3,
        "secondary_public_key_prefix": sec_pub[:12] + "...",
        "activation_token_prefix": activation[:12] + "...",
    }


# ----------------------------
# Lambda handler
# ----------------------------
def lambda_handler(event, context):
    """
    Event modes:
      {"validate_only": true}
      {"run_failover": true}  (default if not provided)
    """

    ca_file = load_ca_to_tmp()
    http = build_http(ca_file)

    # tokens from Secrets Manager
    root_a = read_token_from_secret(VAULT_ROOT_TOKEN_SECRET_ID, VAULT_ROOT_TOKEN_JSON_KEY)

    # IMPORTANT:
    # After Cluster B is promoted, it expects "Cluster A root token or equivalent".
    # In many setups, root token is replicated, so root_a works for Cluster B too.
    # But you can also store a separate Cluster B root token secret and use that if your org does NOT replicate root.
    # For now, we’ll use root_a for both unless you add a separate secret.
    root_b = root_a

    dr_batch = read_token_from_secret(VAULT_DR_BATCH_TOKEN_SECRET_ID, VAULT_DR_BATCH_TOKEN_JSON_KEY)

    if event.get("validate_only"):
        a = get_dr_status(http, CLUSTER_A_ADDR, root_a)
        b = get_dr_status(http, CLUSTER_B_ADDR, root_b)
        return {
            "statusCode": 200,
            "cluster_a_addr": CLUSTER_A_ADDR,
            "cluster_b_addr": CLUSTER_B_ADDR,
            "cluster_a_dr_mode": a.get("mode"),
            "cluster_a_dr_state": a.get("state"),
            "cluster_b_dr_mode": b.get("mode"),
            "cluster_b_dr_state": b.get("state"),
        }

    # --- Controlled failover ---
    step1 = demote_cluster_a_primary(http, root_a)
    step2 = promote_cluster_b_dr(http, root_b, dr_batch)

    # --- Reconfigure Cluster A as DR secondary ---
    step3 = make_cluster_a_secondary_again(http, root_a, root_b, dr_batch)

    # --- Verify ---
    a_after = get_dr_status(http, CLUSTER_A_ADDR, root_a)
    b_after = get_dr_status(http, CLUSTER_B_ADDR, root_b)

    return {
        "statusCode": 200,

        "cluster_a_addr": CLUSTER_A_ADDR,
        "cluster_b_addr": CLUSTER_B_ADDR,
        "new_secondary_id": NEW_SECONDARY_ID,

        "demote_cluster_a_http": step1,
        "promote_cluster_b_http": step2,

        **step3,

        "cluster_a_dr_mode": a_after.get("mode"),
        "cluster_a_dr_state": a_after.get("state"),
        "cluster_b_dr_mode": b_after.get("mode"),
        "cluster_b_dr_state": b_after.get("state"),
    }