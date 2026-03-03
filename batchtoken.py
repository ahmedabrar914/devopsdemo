import os
import json
import datetime
import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------------
# Config (env vars)
# ----------------------------
VAULT_ADDR = os.environ["VAULT_PRIMARY_ADDR"].rstrip("/")
VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # e.g. "ca_pem" if JSON secret

VAULT_ROOT_TOKEN_SECRET_ID = os.environ["VAULT_ROOT_TOKEN_SECRET_ID"]
VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token")  # JSON key for root token

ROTATED_TOKEN_SECRET_ID = os.environ["ROTATED_TOKEN_SECRET_ID"]
BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h")

# Names from your PDF
POLICY_NAME = "dr-secondary-promotion"
ROLE_NAME = "failover-handler"

# File path in Lambda writable dir
CA_PATH = "/tmp/vault-ca.pem"

secrets = boto3.client("secretsmanager")


# ----------------------------
# Helpers: AWS Secrets
# ----------------------------
def get_secret_value(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if "SecretString" in resp and resp["SecretString"] is not None:
        return resp["SecretString"]
    # binary secret fallback
    return resp["SecretBinary"].decode("utf-8")


def load_root_token() -> str:
    raw = get_secret_value(VAULT_ROOT_TOKEN_SECRET_ID)

    # If it's JSON: {"token": "..."}
    try:
        obj = json.loads(raw)
        tok = obj.get(VAULT_ROOT_TOKEN_JSON_KEY)
        if not tok:
            raise Exception(f"Root token JSON missing key '{VAULT_ROOT_TOKEN_JSON_KEY}'")
        return tok
    except json.JSONDecodeError:
        # If you stored the token as plaintext (not recommended), just return it
        return raw.strip()


def load_ca_to_tmp() -> str:
    raw = get_secret_value(VAULT_CA_SECRET_ID)

    # If CA stored as JSON, extract key; otherwise treat as PEM plaintext
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


# ----------------------------
# Helpers: HTTP client to Vault
# ----------------------------
def build_http(verify_path: str) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.verify = verify_path
    s.headers.update({"Content-Type": "application/json"})
    return s


def vault_req(http: requests.Session, method: str, path: str, token: str, body: dict | None = None):
    url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = http.request(method, url, headers=headers, data=json.dumps(body) if body else None, timeout=10)
    try:
        data = resp.json() if resp.text else {}
    except Exception:
        data = {"raw": resp.text}
    return resp.status_code, data


def require_ok(step: str, status: int, data: dict):
    if 200 <= status < 300:
        return
    errs = data.get("errors")
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": errs,
        "response": data
    }))


# ----------------------------
# Step 1: Ensure policy exists
# ----------------------------
POLICY_HCL = r'''
path "sys/replication/dr/secondary/promote" {
  capabilities = ["update"]
}

path "sys/replication/dr/secondary/update-primary" {
  capabilities = ["update"]
}

# Only if using integrated storage (raft) as the storage backend
path "sys/storage/raft/autopilot/state" {
  capabilities = ["update", "read"]
}
'''.strip() + "\n"


def policy_exists(http: requests.Session, token: str, name: str) -> bool:
    # GET /v1/sys/policy/<name> returns policy if exists
    st, data = vault_req(http, "GET", f"sys/policy/{name}", token)
    if st == 200 and "data" in data:
        return True
    if st == 404:
        return False
    # any other error -> fail
    require_ok("policy_exists", st, data)
    return False


def create_policy(http: requests.Session, token: str, name: str) -> int:
    # PUT /v1/sys/policy/<name> with {"policy": "..."}
    st, data = vault_req(http, "PUT", f"sys/policy/{name}", token, {"policy": POLICY_HCL})
    require_ok("create_policy", st, data)
    return st


# ----------------------------
# Step 2: Ensure token role exists
# ----------------------------
def role_exists(http: requests.Session, token: str, name: str) -> bool:
    st, data = vault_req(http, "GET", f"auth/token/roles/{name}", token)
    if st == 200 and "data" in data:
        return True
    if st == 404:
        return False
    require_ok("role_exists", st, data)
    return False


def create_role(http: requests.Session, token: str, name: str) -> int:
    # Matches your manual:
    # vault write auth/token/roles/failover-handler \
    #   allowed_policies=dr-secondary-promotion \
    #   orphan=true \
    #   renewable=false \
    #   token_type=batch
    payload = {
        "allowed_policies": POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch",
        # Keep default policy included (manual output includes "default")
        # If you wanted to remove it, set: "token_no_default_policy": True
    }
    st, data = vault_req(http, "POST", f"auth/token/roles/{name}", token, payload)
    require_ok("create_role", st, data)
    return st


# ----------------------------
# Step 3: Create batch token (manual-equivalent)
# ----------------------------
def create_batch_token(http: requests.Session, token: str, role_name: str, ttl: str):
    # Manual equivalent:
    # vault token create -role=failover-handler -ttl=24h
    #
    # Correct API call:
    # POST /v1/auth/token/create/<role_name> with {"ttl":"24h"}
    st, data = vault_req(http, "POST", f"auth/token/create/{role_name}", token, {"ttl": ttl})
    require_ok("create_batch_token", st, data)

    auth = data.get("auth") or {}
    client_token = auth.get("client_token")
    accessor = auth.get("accessor")  # batch token often shows "n/a" in CLI; API may give "" or omit
    ttl_seconds = auth.get("lease_duration")
    policies = auth.get("policies") or []

    if not client_token:
        raise Exception(json.dumps({"step": "create_batch_token", "error": "client_token missing", "response": data}))

    # Convert TTL string like "24h" to "token_duration" same as CLI output
    token_duration = ttl  # keep exactly as configured (like manual shows 24h)

    # CLI shows token_accessor as "n/a" for batch token. Force that format.
    token_accessor_cli = "n/a"

    # created_at in Zulu
    created_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    return {
        "token": client_token,
        "token_accessor": token_accessor_cli,
        "token_duration": token_duration,
        "token_duration_seconds": ttl_seconds,
        "token_renewable": False,  # batch tokens are not renewable (and your role sets renewable=false)
        "token_policies": policies,
        "identity_policies": auth.get("identity_policies") or [],
        "policies": policies,
        "created_at": created_at,
        "role_name": role_name,
        "vault_addr": VAULT_ADDR,
    }


def store_rotated_token(payload: dict):
    secrets.put_secret_value(
        SecretId=ROTATED_TOKEN_SECRET_ID,
        SecretString=json.dumps(payload)
    )


# ----------------------------
# Lambda handler
# ----------------------------
def lambda_handler(event, context):
    # 1) Load TLS CA + root token
    ca_path = load_ca_to_tmp()
    root_token = load_root_token()

    http = build_http(ca_path)

    result = {
        "vault_primary_addr": VAULT_ADDR,
        "policy_name": POLICY_NAME,
        "role_name": ROLE_NAME,
        "batch_token_ttl": BATCH_TOKEN_TTL,
    }

    # 2) Ensure policy exists (create if missing)
    pol_exists = policy_exists(http, root_token, POLICY_NAME)
    result["policy_existed"] = pol_exists
    if not pol_exists:
        result["policy_create_http"] = create_policy(http, root_token, POLICY_NAME)
    else:
        result["policy_create_http"] = None

    # 3) Ensure role exists (create if missing)
    r_exists = role_exists(http, root_token, ROLE_NAME)
    result["role_existed"] = r_exists
    if not r_exists:
        result["role_create_http"] = create_role(http, root_token, ROLE_NAME)
    else:
        result["role_create_http"] = None

    # 4) Create batch token using role endpoint (manual-equivalent)
    token_payload = create_batch_token(http, root_token, ROLE_NAME, BATCH_TOKEN_TTL)

    # 5) Store in Secrets Manager in “manual-like” key/value style
    store_rotated_token(token_payload)

    # For console output
    result["token_stored_in_secret"] = ROTATED_TOKEN_SECRET_ID
    result["created_at"] = token_payload["created_at"]
    result["token_prefix"] = token_payload["token"].split(".", 1)[0] + "."  # should be "hvb."

    return {
        "statusCode": 200,
        "body": json.dumps(result)
    }