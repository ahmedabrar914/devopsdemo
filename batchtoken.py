import os
import json
import base64
import datetime
import boto3
import urllib3

secrets = boto3.client("secretsmanager")

# -----------------------------
# ENV VARIABLES
# -----------------------------
VAULT_ADDR = os.environ["VAULT_PRIMARY_ADDR"].rstrip("/")

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]
ROTATED_TOKEN_SECRET_ID = os.environ["ROTATED_TOKEN_SECRET_ID"]

VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token")
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY", "")

POLICY_NAME = os.environ.get("POLICY_NAME", "dr-secondary-promotion")
ROLE_NAME = os.environ.get("ROLE_NAME", "failover-handler")
BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h")

CA_PATH = "/tmp/vault-ca.pem"


# -----------------------------
# SECRET HELPERS
# -----------------------------
def get_secret(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]
    return base64.b64decode(resp["SecretBinary"]).decode("utf-8")


def extract_value(secret_payload: str, json_key: str | None) -> str:
    if not json_key:
        return secret_payload

    try:
        obj = json.loads(secret_payload)
        return obj.get(json_key)
    except Exception:
        return secret_payload


def load_root_token() -> str:
    payload = get_secret(VAULT_ROOT_TOKEN_SECRET_ID)
    token = extract_value(payload, VAULT_ROOT_TOKEN_JSON_KEY).strip()
    return token


def load_ca_to_tmp():
    payload = get_secret(VAULT_CA_SECRET_ID)
    pem = extract_value(payload, VAULT_CA_SECRET_JSON_KEY).strip()
    with open(CA_PATH, "w") as f:
        f.write(pem + "\n")


# -----------------------------
# VAULT REQUEST
# -----------------------------
def vault_request(method: str, path: str, token: str, body: dict | None = None):
    url = f"{VAULT_ADDR}/v1/{path}"
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json"
    }

    http = urllib3.PoolManager(
        cert_reqs="CERT_REQUIRED",
        ca_certs=CA_PATH
    )

    encoded = None
    if body:
        encoded = json.dumps(body).encode("utf-8")

    resp = http.request(method, url, body=encoded, headers=headers)

    data = {}
    if resp.data:
        data = json.loads(resp.data.decode("utf-8"))

    return resp.status, data


def require_ok(step, status, data):
    if 200 <= status < 300:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "errors": data.get("errors"),
        "response": data
    }))


# -----------------------------
# ENSURE POLICY
# -----------------------------
POLICY_HCL = """
path "sys/replication/dr/secondary/promote" {
  capabilities = ["update"]
}

path "sys/replication/dr/secondary/update-primary" {
  capabilities = ["update"]
}

path "sys/storage/raft/autopilot/state" {
  capabilities = ["update","read"]
}
"""


def ensure_policy(root_token):
    st, _ = vault_request("GET", f"sys/policies/acl/{POLICY_NAME}", root_token)
    if st == 200:
        return True

    st, data = vault_request(
        "PUT",
        f"sys/policies/acl/{POLICY_NAME}",
        root_token,
        {"policy": POLICY_HCL}
    )
    require_ok("create_policy", st, data)
    return False


# -----------------------------
# ENSURE ROLE
# -----------------------------
def ensure_role(root_token):
    st, _ = vault_request("GET", f"auth/token/roles/{ROLE_NAME}", root_token)
    if st == 200:
        return True

    body = {
        "allowed_policies": POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch"
    }

    st, data = vault_request(
        "POST",
        f"auth/token/roles/{ROLE_NAME}",
        root_token,
        body
    )
    require_ok("create_role", st, data)
    return False


# -----------------------------
# CREATE BATCH TOKEN
# -----------------------------
def create_batch_token(root_token):
    st, data = vault_request(
        "POST",
        f"auth/token/create/{ROLE_NAME}",  # IMPORTANT
        root_token,
        {"ttl": BATCH_TOKEN_TTL}
    )
    require_ok("create_batch_token", st, data)

    auth = data["auth"]

    client_token = auth["client_token"]
    lease_duration = auth.get("lease_duration", 0)
    accessor = auth.get("accessor", "n/a")

    return client_token, accessor, lease_duration


# -----------------------------
# STORE IN KEY/VALUE FORMAT
# -----------------------------
def store_rotated_token(token, accessor, ttl_seconds):
    created_at = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # EXACT key/value format like CLI
    kv_payload = {
        "token": token,
        "token_accessor": accessor or "n/a",
        "token_duration": BATCH_TOKEN_TTL,
        "token_renewable": "false",
        "token_policies": f'["default","{POLICY_NAME}"]',
        "identity_policies": "[]",
        "policies": f'["default","{POLICY_NAME}"]',
        "created_at": created_at
    }

    # THIS makes it appear in Key/Value tab
    secrets.put_secret_value(
        SecretId=ROTATED_TOKEN_SECRET_ID,
        SecretString=json.dumps(kv_payload)
    )

    return created_at


# -----------------------------
# LAMBDA HANDLER
# -----------------------------
def lambda_handler(event, context):

    load_ca_to_tmp()
    root_token = load_root_token()

    policy_existed = ensure_policy(root_token)
    role_existed = ensure_role(root_token)

    token, accessor, ttl_seconds = create_batch_token(root_token)

    created_at = store_rotated_token(token, accessor, ttl_seconds)

    return {
        "statusCode": 200,
        "vault_primary_addr": VAULT_ADDR,
        "policy_name": POLICY_NAME,
        "policy_existed": policy_existed,
        "role_name": ROLE_NAME,
        "role_existed": role_existed,
        "batch_token_ttl": BATCH_TOKEN_TTL,
        "token_prefix": token.split(".", 1)[0],
        "created_at": created_at,
        "stored_in_secret": ROTATED_TOKEN_SECRET_ID
    }