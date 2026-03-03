import os
import json
import datetime
import boto3
import urllib3
from urllib3.util.retry import Retry

# ----------------------------
# Env
# ----------------------------
PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # e.g. ca_pem

VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]
VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY")  # e.g. token (if JSON secret)

ROTATED_TOKEN_SECRET_ID = os.environ["ROTATED_TOKEN_SECRET_ID"]
BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h")

CA_PATH = "/tmp/vault-ca.pem"

POLICY_NAME = "dr-secondary-promotion"
ROLE_NAME = "failover-handler"

secrets = boto3.client("secretsmanager")


# ----------------------------
# Secrets helpers
# ----------------------------
def read_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def load_ca_to_tmp() -> str:
    secret_val = read_secret_string(VAULT_CA_SECRET_ID)
    if VAULT_CA_SECRET_JSON_KEY:
        obj = json.loads(secret_val)
        pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
    else:
        pem = secret_val

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception("Invalid CA PEM in CA secret")

    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(pem)

    return CA_PATH


def get_root_token() -> str:
    secret_val = read_secret_string(VAULT_ROOT_TOKEN_SECRET_ID)
    if VAULT_ROOT_TOKEN_JSON_KEY:
        obj = json.loads(secret_val)
        tok = obj.get(VAULT_ROOT_TOKEN_JSON_KEY)
    else:
        tok = secret_val.strip()

    if not tok or len(tok) < 10:
        raise Exception("Invalid root/admin token in root token secret")

    return tok.strip()


# ----------------------------
# HTTP + Vault API helpers
# ----------------------------
def build_http(ca_file_path: str):
    retries = Retry(
        total=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "LIST"],
        raise_on_status=False,
    )
    return urllib3.PoolManager(retries=retries, cert_reqs="CERT_REQUIRED", ca_certs=ca_file_path)


def _parse_json(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    return json.loads(txt) if txt else {}


def vault_req(http, method: str, token: str, path: str, payload: dict | None = None):
    url = f"{PRIMARY_ADDR.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}

    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")

    resp = http.request(method, url, headers=headers, body=body, timeout=urllib3.Timeout(connect=5, read=30))
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
# Policy & Role existence checks
# ----------------------------
def policy_exists(http, token: str) -> bool:
    # LIST sys/policies/acl returns {"data":{"keys":[...]}}
    st, data = vault_req(http, "LIST", token, "sys/policies/acl")
    if st not in (200, 204):
        # Some envs block LIST; fallback: try read the policy directly
        st2, data2 = vault_req(http, "GET", token, f"sys/policies/acl/{POLICY_NAME}")
        return st2 == 200 and (data2.get("data") is not None)
    keys = (data.get("data") or {}).get("keys") or []
    return POLICY_NAME in keys


def ensure_policy(http, token: str):
    policy_hcl = """
path "sys/replication/dr/secondary/promote" {
  capabilities = ["update"]
}

path "sys/replication/dr/secondary/update-primary" {
  capabilities = ["update"]
}

# Only if using integrated storage (raft)
path "sys/storage/raft/autopilot/state" {
  capabilities = ["update", "read"]
}
""".strip()

    st, data = vault_req(http, "PUT", token, f"sys/policies/acl/{POLICY_NAME}", {"policy": policy_hcl})
    require_ok("ensure_policy", st, data)
    return st


def role_exists(http, token: str) -> bool:
    # Try read role: GET auth/token/roles/<role>
    st, data = vault_req(http, "GET", token, f"auth/token/roles/{ROLE_NAME}")
    return st == 200 and (data.get("data") is not None)


def ensure_role(http, token: str):
    payload = {
        "allowed_policies": POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch"
    }
    st, data = vault_req(http, "POST", token, f"auth/token/roles/{ROLE_NAME}", payload)
    require_ok("ensure_role", st, data)
    return st


# ----------------------------
# Create batch token + store
# ----------------------------
def create_batch_token(http, token: str):
    payload = {"role_name": ROLE_NAME, "ttl": BATCH_TOKEN_TTL}
    st, data = vault_req(http, "POST", token, "auth/token/create", payload)
    require_ok("create_batch_token", st, data)

    auth = data.get("auth") or {}
    client_token = auth.get("client_token")
    accessor = auth.get("accessor")
    ttl_seconds = auth.get("lease_duration")

    if not client_token:
        raise Exception(json.dumps({"step": "create_batch_token", "error": "client_token missing", "response": data}))
    return client_token, accessor, ttl_seconds


def store_rotated_token(token: str, accessor: str | None, ttl_seconds: int | None):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    payload = {
        "token": token,
        "ttl": BATCH_TOKEN_TTL,
        "ttl_seconds": ttl_seconds,
        "accessor": accessor,
        "created_at": now
    }
    secrets.put_secret_value(
        SecretId=ROTATED_TOKEN_SECRET_ID,
        SecretString=json.dumps(payload)
    )
    return payload


def lambda_handler(event, context):
    ca_file = load_ca_to_tmp()
    http = build_http(ca_file)

    root_token = get_root_token()

    # Policy check -> create if missing
    policy_was_present = policy_exists(http, root_token)
    policy_http = None
    if not policy_was_present:
        policy_http = ensure_policy(http, root_token)

    # Role check -> create if missing
    role_was_present = role_exists(http, root_token)
    role_http = None
    if not role_was_present:
        role_http = ensure_role(http, root_token)

    # Always rotate token
    batch_token, accessor, ttl_seconds = create_batch_token(http, root_token)
    stored = store_rotated_token(batch_token, accessor, ttl_seconds)

    return {
        "statusCode": 200,
        "vault_primary_addr": PRIMARY_ADDR,

        "policy_name": POLICY_NAME,
        "policy_existed": policy_was_present,
        "policy_create_http": policy_http,

        "role_name": ROLE_NAME,
        "role_existed": role_was_present,
        "role_create_http": role_http,

        "batch_token_ttl": BATCH_TOKEN_TTL,
        "token_stored_in_secret": ROTATED_TOKEN_SECRET_ID,
        "token_prefix": batch_token[:12] + "...",
        "created_at": stored["created_at"]
    }