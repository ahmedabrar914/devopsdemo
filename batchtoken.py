import os
import json
import base64
import datetime
import boto3
import urllib3

secrets = boto3.client("secretsmanager")

# ---------------------------
# Env vars (required)
# ---------------------------
VAULT_PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"].rstrip("/")  # e.g. https://usw2.dev.vault.corp.zscaler.com:8200

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]              # secret that stores CA PEM
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY", "")  # optional, e.g. "ca_pem"

VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]       # secret that stores root token
VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token")

ROTATED_TOKEN_SECRET_ID = os.environ["ROTATED_TOKEN_SECRET_ID"]    # where to store created batch token result

BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h")         # 24h / 48h etc.

# Policy/Role names (as per your PDF)
POLICY_NAME = os.environ.get("POLICY_NAME", "dr-secondary-promotion")
ROLE_NAME = os.environ.get("ROLE_NAME", "failover-handler")

CA_PATH = "/tmp/vault-ca.pem"


# ---------------------------
# Helpers: Secrets Manager
# ---------------------------
def _get_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]
    return base64.b64decode(resp["SecretBinary"]).decode("utf-8")


def _extract_value(secret_payload: str, json_key: str | None) -> str:
    """
    If secret is JSON and json_key is provided, return that field.
    Else return raw string.
    """
    if not json_key:
        return secret_payload

    try:
        obj = json.loads(secret_payload)
        if json_key in obj:
            return obj[json_key]
    except Exception:
        pass

    # fallback (secret was not JSON)
    return secret_payload


def load_ca_to_tmp() -> None:
    ca_payload = _get_secret_string(VAULT_CA_SECRET_ID)
    ca_pem = _extract_value(ca_payload, VAULT_CA_SECRET_JSON_KEY).strip()
    if not ca_pem.startswith("-----BEGIN"):
        raise Exception("CA secret does not look like PEM. Store full PEM text in Secrets Manager.")
    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(ca_pem + "\n")


def load_root_token() -> str:
    tok_payload = _get_secret_string(VAULT_ROOT_TOKEN_SECRET_ID)
    token = _extract_value(tok_payload, VAULT_ROOT_TOKEN_JSON_KEY).strip()
    if not token or not token.startswith("hv"):
        raise Exception("Root token looks invalid. Ensure secret contains JSON key 'token' with value like 'hvs....'")
    return token


def store_rotated_token_kv(secret_id: str, kv: dict) -> None:
    # store as JSON key/value (same fields as CLI-style output)
    secrets.put_secret_value(
        SecretId=secret_id,
        SecretString=json.dumps(kv, separators=(",", ":"), ensure_ascii=False),
    )


# ---------------------------
# Helpers: Vault HTTP
# ---------------------------
def vault_request(method: str, path: str, token: str, body: dict | None = None):
    """
    path should be like: 'sys/policies/acl/<name>' (no leading /v1)
    """
    url = f"{VAULT_PRIMARY_ADDR}/v1/{path.lstrip('/')}"
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    http = urllib3.PoolManager(
        cert_reqs="CERT_REQUIRED",
        ca_certs=CA_PATH,
        timeout=urllib3.Timeout(connect=5.0, read=15.0),
        retries=False,
    )

    resp = http.request(method.upper(), url, body=data, headers=headers)
    raw = resp.data.decode("utf-8") if resp.data else ""
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        payload = {"raw": raw}

    return resp.status, payload


def require_ok(step: str, status: int, payload: dict, ok=(200, 204)):
    if status in ok:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": payload.get("errors"),
        "response": payload
    }))


# ---------------------------
# Vault objects: Policy + Role
# ---------------------------
POLICY_HCL = r'''
path "sys/replication/dr/secondary/promote" {
  capabilities = ["update"]
}

path "sys/replication/dr/secondary/update-primary" {
  capabilities = ["update"]
}

path "sys/storage/raft/autopilot/state" {
  capabilities = ["update", "read"]
}
'''.strip() + "\n"


def ensure_policy(root_token: str) -> dict:
    # GET policy
    st, data = vault_request("GET", f"sys/policies/acl/{POLICY_NAME}", root_token)
    if st == 200:
        return {"policy_existed": True, "policy_create_http": None}

    # If not found, create
    if st not in (404,):
        require_ok("policy_check", st, data)

    st2, data2 = vault_request("PUT", f"sys/policies/acl/{POLICY_NAME}", root_token, {"policy": POLICY_HCL})
    require_ok("policy_create", st2, data2, ok=(200, 204))
    return {"policy_existed": False, "policy_create_http": st2}


def ensure_role(root_token: str) -> dict:
    # GET role
    st, data = vault_request("GET", f"auth/token/roles/{ROLE_NAME}", root_token)
    if st == 200:
        return {"role_existed": True, "role_create_http": None}

    if st not in (404,):
        require_ok("role_check", st, data)

    # Create role (matches PDF)
    body = {
        "allowed_policies": POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch",
    }
    st2, data2 = vault_request("POST", f"auth/token/roles/{ROLE_NAME}", root_token, body)
    require_ok("role_create", st2, data2, ok=(200, 204))
    return {"role_existed": False, "role_create_http": st2}


def create_batch_token(root_token: str):
    """
    Use token role when creating (so token_type=batch is enforced by role).
    Two valid options:
      A) POST auth/token/create/<role>   body: {"ttl":"24h"}
      B) POST auth/token/create          body: {"role_name":"<role>", "ttl":"24h"}
    We'll use (A) to be closest to CLI `-role=<role>`.
    """
    st, data = vault_request("POST", f"auth/token/create/{ROLE_NAME}", root_token, {"ttl": BATCH_TOKEN_TTL})
    require_ok("create_batch_token", st, data)

    auth = data.get("auth") or {}
    client_token = auth.get("client_token")  # <-- should start with hvb... for batch tokens
    accessor = auth.get("accessor")          # may be empty/n/a for batch tokens
    lease_duration = auth.get("lease_duration")  # seconds

    if not client_token:
        raise Exception(json.dumps({"step": "create_batch_token", "error": "client_token missing", "response": data}))

    return client_token, accessor, lease_duration, auth


def seconds_to_human(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    # keep it simple: prefer hours if divisible
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


# ---------------------------
# Lambda handler
# ---------------------------
def lambda_handler(event, context):
    load_ca_to_tmp()
    root_token = load_root_token()

    # 1) ensure policy and role exist
    pol = ensure_policy(root_token)
    role = ensure_role(root_token)

    # 2) create batch token
    token, accessor, ttl_seconds, _auth = create_batch_token(root_token)
    created_at = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    # 3) store EXACTLY like CLI table (key/value) + created_at
    kv = {
        "token": token,
        "token_accessor": accessor or "n/a",
        "token_duration": seconds_to_human(ttl_seconds) or BATCH_TOKEN_TTL,  # what you SEE in CLI (24h)
        "token_renewable": False,
        "token_policies": ["default", POLICY_NAME],
        "identity_policies": [],
        "policies": ["default", POLICY_NAME],
        "created_at": created_at,
    }

    store_rotated_token_kv(ROTATED_TOKEN_SECRET_ID, kv)

    return {
        "statusCode": 200,
        "vault_primary_addr": VAULT_PRIMARY_ADDR,
        "policy_name": POLICY_NAME,
        **pol,
        "role_name": ROLE_NAME,
        **role,
        "batch_token_ttl": BATCH_TOKEN_TTL,
        "token_prefix": token.split(".", 1)[0],  # hvb vs hvs
        "created_at": created_at,
        "token_stored_in_secret": ROTATED_TOKEN_SECRET_ID,
    }