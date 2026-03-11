import os
import json
import time
import ssl
import subprocess
import urllib.request
import urllib.error

PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

PRIMARY_TOKEN_SECRET_ID = os.environ["VAULT_PRIMARY_TOKEN_SECRET_ID"]
FAILOVER_TOKEN_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]

VAULT_TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "root_token")
FAILOVER_TOKEN_JSON_KEY = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

POST_PROMOTE_SLEEP_SECONDS = int(os.environ.get("POST_PROMOTE_SLEEP_SECONDS", "8"))
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
RUN_MODE = os.environ.get("RUN_MODE", "validate_only").strip().lower()


def run_cmd(cmd):
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


def get_secret_value(secret_id: str) -> str:
    cmd = [
        "aws", "secretsmanager", "get-secret-value",
        "--secret-id", secret_id,
        "--region", AWS_REGION,
        "--output", "json"
    ]

    rc, stdout, stderr = run_cmd(cmd)
    if rc != 0:
        raise Exception(json.dumps({
            "step": "get_secret_value",
            "secret_id": secret_id,
            "error": "failed to fetch secret from Secrets Manager",
            "return_code": rc,
            "stderr": stderr.strip()
        }))

    resp = json.loads(stdout)

    if resp.get("SecretString"):
        return resp["SecretString"]

    if resp.get("SecretBinary"):
        return resp["SecretBinary"]

    raise Exception(json.dumps({
        "step": "get_secret_value",
        "secret_id": secret_id,
        "error": "secret does not contain SecretString or SecretBinary"
    }))


def try_parse_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def load_token_from_secret(secret_id: str, json_key: str) -> str:
    secret_val = get_secret_value(secret_id).strip()

    if not secret_val.startswith("{"):
        if not secret_val:
            raise Exception(json.dumps({
                "step": "load_token_from_secret",
                "secret_id": secret_id,
                "error": "token secret is empty"
            }))
        return secret_val

    obj = try_parse_json(secret_val)
    if obj is None or not isinstance(obj, dict):
        raise Exception(json.dumps({
            "step": "load_token_from_secret",
            "secret_id": secret_id,
            "error": "token secret looks like JSON but could not be parsed"
        }))

    token = obj.get(json_key)
    if token:
        return str(token).strip()

    for key in ["root_token", "token", "vault_token"]:
        if obj.get(key):
            return str(obj[key]).strip()

    raise Exception(json.dumps({
        "step": "load_token_from_secret",
        "secret_id": secret_id,
        "error": f"token key not found in JSON secret; tried '{json_key}', 'root_token', 'token', 'vault_token'"
    }))


def build_ssl_context():
    print("Using insecure TLS mode without CA for bastion test")
    return ssl._create_unverified_context()


def parse_json_bytes(data: bytes):
    if not data:
        return {}
    txt = data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {"raw_response": txt}


def vault_request(method: str, addr: str, token: str = "", path: str = "", payload=None, ssl_context=None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {}

    if token:
        headers["X-Vault-Token"] = token

    if method == "POST":
        headers["Content-Type"] = "application/json"

    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=40) as resp:
            return resp.getcode(), parse_json_bytes(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, parse_json_bytes(e.read())
    except urllib.error.URLError as e:
        raise Exception(json.dumps({
            "step": f"{method} {path}",
            "error": "URL error while calling Vault API",
            "url": url,
            "details": str(e.reason)
        }))
    except Exception as e:
        raise Exception(json.dumps({
            "step": f"{method} {path}",
            "error": "unexpected error while calling Vault API",
            "url": url,
            "details": str(e)
        }))


def vault_get(ssl_context, addr: str, token: str, path: str):
    return vault_request("GET", addr, token, path, payload=None, ssl_context=ssl_context)


def vault_post(ssl_context, addr: str, token: str, path: str, payload=None):
    return vault_request("POST", addr, token, path, payload=payload or {}, ssl_context=ssl_context)


def require_ok(step: str, status: int, data: dict, ok=(200, 204)):
    if status in ok:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": status,
        "vault_errors": data.get("errors"),
        "response": data
    }, default=str))


def dr_status(ssl_context, addr: str, token: str):
    st, data = vault_get(ssl_context, addr, token, "sys/replication/dr/status")
    return {"http": st, "data": data}


def health(ssl_context, addr: str):
    st, data = vault_request("GET", addr, "", "sys/health", payload=None, ssl_context=ssl_context)
    return {"http": st, "data": data}


def get_failover_token() -> str:
    raw = get_secret_value(FAILOVER_TOKEN_SECRET_ID).strip()

    if not raw.startswith("{"):
        if not raw:
            raise Exception(json.dumps({
                "step": "get_failover_token",
                "secret_id": FAILOVER_TOKEN_SECRET_ID,
                "error": "failover token secret is empty"
            }))
        return raw

    obj = try_parse_json(raw)
    if obj is None or not isinstance(obj, dict):
        raise Exception(json.dumps({
            "step": "get_failover_token",
            "secret_id": FAILOVER_TOKEN_SECRET_ID,
            "error": "failover token secret looks like JSON but could not be parsed"
        }))

    tok = obj.get(FAILOVER_TOKEN_JSON_KEY)
    if tok:
        return str(tok).strip()

    for key in ["token", "dr_operation_token", "failover_token"]:
        if obj.get(key):
            return str(obj[key]).strip()

    raise Exception(json.dumps({
        "step": "get_failover_token",
        "secret_id": FAILOVER_TOKEN_SECRET_ID,
        "error": f"failover token key not found in JSON secret; tried '{FAILOVER_TOKEN_JSON_KEY}', 'token', 'dr_operation_token', 'failover_token'"
    }))


def run_controlled_failover(validate_only: bool = False):
    print("Loading Vault tokens from Secrets Manager")
    primary_token = load_token_from_secret(PRIMARY_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)
    batch_token = get_failover_token()

    print("Building insecure SSL context")
    ssl_context = build_ssl_context()

    if validate_only:
        return {
            "statusCode": 200,
            "mode": "controlled_failover_validate_only",
            "primary_health": health(ssl_context, PRIMARY_ADDR),
            "secondary_health": health(ssl_context, SECONDARY_ADDR),
            "primary_dr_status": dr_status(ssl_context, PRIMARY_ADDR, primary_token),
            "secondary_dr_status": dr_status(ssl_context, SECONDARY_ADDR, primary_token)
        }

    steps = {}

    print("Step 1: Demote cluster A")
    st1, d1 = vault_post(
        ssl_context,
        PRIMARY_ADDR,
        primary_token,
        "sys/replication/dr/primary/demote",
        payload={}
    )
    print(f"Step 1 HTTP status: {st1}")
    require_ok("step1_demote_cluster_a", st1, d1)
    steps["step1_demote_cluster_a"] = {"http": st1, "response": d1}

    print("Step 2: Promote cluster B")
    st2, d2 = vault_post(
        ssl_context,
        SECONDARY_ADDR,
        primary_token,
        "sys/replication/dr/secondary/promote",
        payload={"dr_operation_token": batch_token}
    )
    print(f"Step 2 HTTP status: {st2}")
    require_ok("step2_promote_cluster_b", st2, d2)
    steps["step2_promote_cluster_b"] = {"http": st2, "response": d2}

    print(f"Sleeping {POST_PROMOTE_SLEEP_SECONDS}s after promotion")
    time.sleep(POST_PROMOTE_SLEEP_SECONDS)

    print("Step 3: Verify cluster B DR status")
    verify = dr_status(ssl_context, SECONDARY_ADDR, primary_token)
    steps["step3_verify_cluster_b"] = verify

    return {
        "statusCode": 200,
        "mode": "controlled_failover",
        "steps": steps,
        "expected": {"cluster_b_mode_should_be": "primary"}
    }


if __name__ == "__main__":
    if RUN_MODE == "validate_only":
        result = run_controlled_failover(validate_only=True)
    elif RUN_MODE == "execute":
        result = run_controlled_failover(validate_only=False)
    else:
        result = {
            "statusCode": 500,
            "error": f"Unsupported RUN_MODE: {RUN_MODE}"
        }

    print(json.dumps(result, indent=2))
    if result.get("statusCode") != 200:
        raise SystemExit(1)