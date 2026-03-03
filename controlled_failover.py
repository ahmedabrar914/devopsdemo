import os
import json
import time
import boto3
import urllib3
from urllib3.util.retry import Retry

secrets = boto3.client("secretsmanager")

CA_PATH = "/tmp/vault-ca.pem"


# ----------------------------
# Read existing env vars (YOUR NAMES)
# ----------------------------
PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]         # Cluster A (old primary)
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]     # Cluster B (DR)

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]

# DR operations batch token (already in your env)
DR_BATCH_TOKEN_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]

# NEW: root token secret ids
PRIMARY_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_PRIMARY_TOKEN_SECRET_ID"]
SECONDARY_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_SECONDARY_TOKEN_SECRET_ID"]

# Used as the "id" when generating secondary token on new primary (Cluster B)
# Your env has VAULT_PRIMARY_CLUSTER_ID=usw2, perfect to use as stable id.
CLUSTER_A_ID = os.environ.get("VAULT_PRIMARY_CLUSTER_ID", "cluster-a")

# optional keys (if secrets are JSON key/value; your screenshot shows token key)
TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "token")  # default "token"


# ----------------------------
# Secrets helpers
# ----------------------------
def _get_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if resp.get("SecretString"):
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def read_token(secret_id: str) -> str:
    raw = _get_secret_string(secret_id).strip()
    if raw.startswith("{"):
        obj = json.loads(raw)
        tok = obj.get(TOKEN_JSON_KEY)
    else:
        tok = raw
    if not tok:
        raise Exception(f"Token not found in secret: {secret_id}")
    return tok.strip()


def load_ca_to_tmp() -> str:
    raw = _get_secret_string(VAULT_CA_SECRET_ID).strip()

    # If CA is stored as JSON, set VAULT_CA_SECRET_JSON_KEY and parse. If plain PEM, use directly.
    ca_json_key = os.environ.get("VAULT_CA_SECRET_JSON_KEY")
    if ca_json_key and raw.startswith("{"):
        raw = json.loads(raw).get(ca_json_key, "")

    if "BEGIN CERTIFICATE" not in raw:
        raise Exception("CA PEM not valid (missing BEGIN CERTIFICATE)")

    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(raw)

    return CA_PATH


# ----------------------------
# HTTP client
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
    return json.loads(txt) if txt else {}


def vault_post(http, addr: str, token: str, path: str, payload: dict | None = None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    body = json.dumps(payload or {}).encode("utf-8")
    resp = http.request("POST", url, headers=headers, body=body, timeout=urllib3.Timeout(connect=5, read=60))
    return resp.status, _parse_json(resp)


def vault_get(http, addr: str, token: str, path: str):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = http.request("GET", url, headers=headers, timeout=urllib3.Timeout(connect=5, read=30))
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


def dr_status(http, addr: str, token: str) -> dict:
    st, data = vault_get(http, addr, token, "sys/replication/dr/status")
    if st == 200:
        d = data.get("data") or {}
        return {"http": st, "mode": d.get("mode"), "state": d.get("state"), "primary_cluster_addr": d.get("primary_cluster_addr")}
    st2, data2 = vault_get(http, addr, token, "sys/replication/status")
    d2 = (data2.get("data") or {}).get("dr") or {}
    return {"http": st2, "mode": d2.get("mode"), "state": d2.get("state"), "primary_cluster_addr": d2.get("primary_cluster_addr")}


# ----------------------------
# Controlled Failover
# ----------------------------
def controlled_failover(http, root_a: str, root_b: str, dr_batch_token: str) -> dict:
    # 1) Demote Cluster A (Primary) first
    st1, d1 = vault_post(http, PRIMARY_ADDR, root_a, "sys/replication/dr/primary/demote", {})
    require_ok("demote_cluster_a", st1, d1)

    time.sleep(5)

    # 2) Promote Cluster B (DR) using dr_operation_token (batch token)
    st2, d2 = vault_post(http, SECONDARY_ADDR, root_b, "sys/replication/dr/secondary/promote",
                        {"dr_operation_token": dr_batch_token})
    require_ok("promote_cluster_b", st2, d2)

    time.sleep(8)

    # 3) Now Cluster B is primary. Make Cluster A the new DR secondary.
    # Step 1 on A: generate-public-key
    st3, d3 = vault_post(http, PRIMARY_ADDR, root_a, "sys/replication/dr/secondary/generate-public-key", {})
    require_ok("cluster_a_generate_public_key", st3, d3)
    secondary_public_key = (d3.get("data") or {}).get("secondary_public_key")
    if not secondary_public_key:
        raise Exception(json.dumps({"step": "cluster_a_generate_public_key", "error": "secondary_public_key missing"}))

    # Step 2 on B: generate activation token (secondary-token)
    st4, d4 = vault_post(http, SECONDARY_ADDR, root_b, "sys/replication/dr/primary/secondary-token",
                        {"secondary_public_key": secondary_public_key, "id": CLUSTER_A_ID})
    require_ok("cluster_b_secondary_token", st4, d4)
    activation_token = (d4.get("data") or {}).get("token")
    if not activation_token:
        raise Exception(json.dumps({"step": "cluster_b_secondary_token", "error": "activation token missing"}))

    # Step 3 on A: update-primary using dr batch token + activation token
    st5, d5 = vault_post(http, PRIMARY_ADDR, root_a, "sys/replication/dr/secondary/update-primary",
                        {"dr_operation_token": dr_batch_token, "token": activation_token})
    require_ok("cluster_a_update_primary", st5, d5)

    # 4) Verify status both sides
    a_stat = dr_status(http, PRIMARY_ADDR, root_a)
    b_stat = dr_status(http, SECONDARY_ADDR, root_b)

    return {
        "demote_http": st1,
        "promote_http": st2,
        "cluster_a_generate_public_key_http": st3,
        "cluster_b_secondary_token_http": st4,
        "cluster_a_update_primary_http": st5,
        "cluster_a_dr_mode": a_stat.get("mode"),
        "cluster_a_dr_state": a_stat.get("state"),
        "cluster_b_dr_mode": b_stat.get("mode"),
        "cluster_b_dr_state": b_stat.get("state"),
        "cluster_a_id_used": CLUSTER_A_ID
    }


def lambda_handler(event, context):
    ca_file = load_ca_to_tmp()
    http = build_http(ca_file)

    root_a = read_token(PRIMARY_ROOT_TOKEN_SECRET_ID)
    root_b = read_token(SECONDARY_ROOT_TOKEN_SECRET_ID)
    dr_batch = read_token(DR_BATCH_TOKEN_SECRET_ID)

    if event.get("validate_only"):
        return {
            "statusCode": 200,
            "primary_addr": PRIMARY_ADDR,
            "secondary_addr": SECONDARY_ADDR,
            "primary_dr": dr_status(http, PRIMARY_ADDR, root_a),
            "secondary_dr": dr_status(http, SECONDARY_ADDR, root_b),
        }

    out = controlled_failover(http, root_a, root_b, dr_batch)
    return {"statusCode": 200, **out}