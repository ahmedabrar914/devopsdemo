import os
import json
import datetime
import boto3
import urllib3
import certifi

secrets = boto3.client("secretsmanager")
http = urllib3.PoolManager()

VAULT_ADDR = os.environ["VAULT_PRIMARY_ADDR"].rstrip("/")

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # optional

VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]
VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token")

ROTATED_TOKEN_SECRET_ID = os.environ["ROTATED_TOKEN_SECRET_ID"]
BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h")

POLICY_NAME = "dr-secondary-promotion"
ROLE_NAME = "failover-handler"

CA_PATH = "/tmp/vault-ca.pem"

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


def get_secret(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def load_root_token() -> str:
    raw = get_secret(VAULT_ROOT_TOKEN_SECRET_ID)
    try:
        obj = json.loads(raw)
        tok = obj.get(VAULT_ROOT_TOKEN_JSON_KEY)
        if not tok:
            raise Exception(f"Root token JSON missing key '{VAULT_ROOT_TOKEN_JSON_KEY}'")
        return tok.strip()
    except json.JSONDecodeError:
        return raw.strip()


def load_ca_to_tmp() -> str:
    raw = get_secret(VAULT_CA_SECRET_ID)

    pem = None
    try:
        obj = json.loads(raw)
        if not VAULT_CA_SECRET_JSON_KEY:
            raise Exception("CA secret is JSON but VAULT_CA_SECRET_JSON_KEY not set")
        pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
        if not pem:
            raise Exception(f"CA JSON missing key '{VAULT_CA_SECRET_JSON_KEY}'")
    except json.JSONDecodeError:
        pem = raw

    pem = pem.strip() + "\n"
    with open(CA_PATH, "w") as f:
        f.write(pem)
    return CA_PATH


def vault_request(method: str, path: str, token: str, body: dict | None = None, ca_path: str | None = None):
    url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json",
    }

    encoded = None
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")

    # verify using CA file we saved
    resp = http.request(
        method,
        url,
        body=encoded,
        headers=headers,
        timeout=urllib3.Timeout(connect=5.0, read=10.0),
        retries=False,
        cert_reqs="CERT_REQUIRED",
        ca_certs=ca_path,
    )

    data = {}
    if resp.data:
        try:
            data = json.loads(resp.data.decode("utf-8"))
        except Exception:
            data = {"raw": resp.data.decode("utf-8", errors="ignore")}

    return resp.status, data


def require_ok(step: str, status: int, data: dict):
    if 200 <= status < 300:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": data.get("errors"),
        "response": data
    }))


def policy_exists(token: str, ca_path: str) -> bool:
    st, data = vault_request("GET", f"sys/policy/{POLICY_NAME}", token, None, ca_path)
    if st == 200:
        return True
    if st == 404:
        return False
    require_ok("policy_exists", st, data)
    return False


def create_policy(token: str, ca_path: str):
    st, data = vault_request("PUT", f"sys/policy/{POLICY_NAME}", token, {"policy": POLICY_HCL}, ca_path)
    require_ok("create_policy", st, data)
    return st


def role_exists(token: str, ca_path: str) -> bool:
    st, data = vault_request("GET", f"auth/token/roles/{ROLE_NAME}", token, None, ca_path)
    if st == 200:
        return True
    if st == 404:
        return False
    require_ok("role_exists", st, data)
    return False


def create_role(token: str, ca_path: str):
    payload = {
        "allowed_policies": POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch",
    }
    st, data = vault_request("POST", f"auth/token/roles/{ROLE_NAME}", token, payload, ca_path)
    require_ok("create_role", st, data)
    return st


def create_batch_token(token: str, ca_path: str):
    # ✅ IMPORTANT: role endpoint, same as manual
    st, data = vault_request("POST", f"auth/token/create/{ROLE_NAME}", token, {"ttl": BATCH_TOKEN_TTL}, ca_path)
    require_ok("create_batch_token", st, data)

    auth = data.get("auth") or {}
    client_token = auth.get("client_token")
    policies = auth.get("policies") or []

    if not client_token:
        raise Exception(json.dumps({"step": "create_batch_token", "error": "client_token missing", "response": data}))

    created_at = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Store EXACTLY like CLI (key/value)
    payload = {
        "token": client_token,
        "token_accessor": "n/a",              # CLI shows n/a for batch tokens
        "token_duration": BATCH_TOKEN_TTL,    # e.g. 24h
        "token_renewable": False,
        "token_policies": policies,
        "identity_policies": [],
        "policies": policies,
        "created_at": created_at
    }

    # Optional: store seconds too (if you want, comment out if not needed)
    lease_seconds = auth.get("lease_duration")
    if lease_seconds is not None:
        payload["token_duration_seconds"] = lease_seconds

    return payload


def store_in_secrets_manager(payload: dict):
    secrets.put_secret_value(
        SecretId=ROTATED_TOKEN_SECRET_ID,
        SecretString=json.dumps(payload)
    )


def lambda_handler(event, context):
    ca_path = load_ca_to_tmp()
    root_token = load_root_token()

    result = {
        "vault_primary_addr": VAULT_ADDR,
        "policy_name": POLICY_NAME,
        "role_name": ROLE_NAME,
        "batch_token_ttl": BATCH_TOKEN_TTL,
    }

    pe = policy_exists(root_token, ca_path)
    result["policy_existed"] = pe
    if not pe:
        result["policy_create_http"] = create_policy(root_token, ca_path)

    re = role_exists(root_token, ca_path)
    result["role_existed"] = re
    if not re:
        result["role_create_http"] = create_role(root_token, ca_path)

    token_payload = create_batch_token(root_token, ca_path)
    store_in_secrets_manager(token_payload)

    result["stored_secret_id"] = ROTATED_TOKEN_SECRET_ID
    result["created_at"] = token_payload["created_at"]
    result["token_prefix"] = token_payload["token"].split(".", 1)[0] + "."

    return {"statusCode": 200, "body": json.dumps(result)}