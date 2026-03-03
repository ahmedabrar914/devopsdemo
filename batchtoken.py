import os
import json
import time
import boto3
import urllib3
from urllib3.util.retry import Retry

# ---- required env ----
PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
PRIMARY_TOKEN = os.environ["VAULT_PRIMARY_TOKEN"]

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # optional, if CA secret is JSON

FAILOVER_POLICY_NAME = os.environ.get("FAILOVER_POLICY_NAME", "dr-secondary-promotion")
FAILOVER_ROLE_NAME   = os.environ.get("FAILOVER_ROLE_NAME", "failover-handler")
FAILOVER_TOKEN_TTL   = os.environ.get("FAILOVER_TOKEN_TTL", "24h")

FAILOVER_TOKEN_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]

CA_PATH = "/tmp/vault-ca.pem"

secrets = boto3.client("secretsmanager")


def _load_ca_to_tmp() -> str:
    resp = secrets.get_secret_value(SecretId=VAULT_CA_SECRET_ID)

    if "SecretString" in resp and resp["SecretString"]:
        raw = resp["SecretString"]
    else:
        raw = resp["SecretBinary"].decode("utf-8")

    if VAULT_CA_SECRET_JSON_KEY:
        raw = json.loads(raw)[VAULT_CA_SECRET_JSON_KEY]

    if "BEGIN CERTIFICATE" not in raw:
        raise Exception("CA PEM missing/invalid in VAULT_CA_SECRET_ID")

    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(raw)

    return CA_PATH


def _http_client(ca_file: str):
    retries = Retry(
        total=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT"],
        raise_on_status=False,
    )
    return urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=ca_file, retries=retries)


def _parse(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    return json.loads(txt) if txt else {}


def _vault_put(http, path: str, payload: dict):
    url = f"{PRIMARY_ADDR.rstrip('/')}/v1/{path.lstrip('/')}"
    r = http.request(
        "PUT",
        url,
        headers={"X-Vault-Token": PRIMARY_TOKEN, "Content-Type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
        timeout=urllib3.Timeout(connect=5, read=30),
    )
    return r.status, _parse(r)


def _vault_post(http, path: str, payload: dict):
    url = f"{PRIMARY_ADDR.rstrip('/')}/v1/{path.lstrip('/')}"
    r = http.request(
        "POST",
        url,
        headers={"X-Vault-Token": PRIMARY_TOKEN, "Content-Type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
        timeout=urllib3.Timeout(connect=5, read=60),
    )
    return r.status, _parse(r)


def _require_ok(step: str, status: int, data: dict):
    if status in (200, 204):
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": data.get("errors"),
        "response": data
    }, default=str))


def _ensure_policy(http):
    # Matches the PDF policy
    policy_hcl = f"""
path "sys/replication/dr/secondary/promote" {{
  capabilities = ["update"]
}}

path "sys/replication/dr/secondary/update-primary" {{
  capabilities = ["update"]
}}

# Only if using integrated storage (raft)
path "sys/storage/raft/autopilot/state" {{
  capabilities = ["update", "read"]
}}
""".strip()

    st, data = _vault_put(http, f"sys/policies/acl/{FAILOVER_POLICY_NAME}", {"policy": policy_hcl})
    _require_ok("ensure_policy", st, data)
    return st


def _ensure_role(http):
    payload = {
        "allowed_policies": FAILOVER_POLICY_NAME,
        "orphan": True,
        "renewable": False,
        "token_type": "batch"
    }
    st, data = _vault_post(http, f"auth/token/roles/{FAILOVER_ROLE_NAME}", payload)
    _require_ok("ensure_role", st, data)
    return st


def _create_batch_token(http):
    st, data = _vault_post(http, f"auth/token/create/{FAILOVER_ROLE_NAME}", {"ttl": FAILOVER_TOKEN_TTL})
    _require_ok("create_batch_token", st, data)

    auth = data.get("auth") or {}
    token = auth.get("client_token")
    lease = auth.get("lease_duration")

    if not token:
        raise Exception(json.dumps({"step": "create_batch_token", "error": "client_token missing", "response": data}))

    return token, lease, auth.get("policies"), auth.get("renewable")


def _upsert_secret(secret_id: str, payload: dict):
    s = json.dumps(payload)
    try:
        secrets.describe_secret(SecretId=secret_id)
        secrets.put_secret_value(SecretId=secret_id, SecretString=s)
        return "updated"
    except secrets.exceptions.ResourceNotFoundException:
        secrets.create_secret(Name=secret_id, SecretString=s)
        return "created"


def run_create_failover_batch_token():
    ca_file = _load_ca_to_tmp()
    http = _http_client(ca_file)

    pol_http = _ensure_policy(http)
    role_http = _ensure_role(http)
    token, lease_seconds, policies, renewable = _create_batch_token(http)

    secret_payload = {
        "token": token,
        "token_duration": FAILOVER_TOKEN_TTL,              # keep as "24h"
        "lease_duration_seconds": lease_seconds,           # Vault returns seconds (optional)
        "policies": policies,
        "renewable": renewable,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "primary_addr": PRIMARY_ADDR,
        "role_name": FAILOVER_ROLE_NAME,
        "policy_name": FAILOVER_POLICY_NAME,
    }

    write_action = _upsert_secret(FAILOVER_TOKEN_SECRET_ID, secret_payload)

    return {
        "policy_http": pol_http,
        "role_http": role_http,
        "token_prefix": token[:12] + "...",
        "token_duration": FAILOVER_TOKEN_TTL,
        "secret_write_action": write_action,
        "secret_id": FAILOVER_TOKEN_SECRET_ID
    }