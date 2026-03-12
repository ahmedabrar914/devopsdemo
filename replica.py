import os
import json
import time
import ssl
import subprocess
import urllib.request
import urllib.error

# ----------------------------
# Required env vars
# ----------------------------
PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

PRIMARY_TOKEN_SECRET_ID = os.environ["VAULT_PRIMARY_TOKEN_SECRET_ID"]
SECONDARY_TOKEN_SECRET_ID = os.environ["VAULT_SECONDARY_TOKEN_SECRET_ID"]

PRIMARY_CLUSTER_ID = os.environ.get("VAULT_PRIMARY_CLUSTER_ID", "usw2")
VAULT_TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "root_token")

POST_ENABLE_SLEEP_SECONDS = int(os.environ.get("POST_ENABLE_SLEEP_SECONDS", "8"))
POST_TOKEN_SLEEP_SECONDS = int(os.environ.get("POST_TOKEN_SLEEP_SECONDS", "15"))
RETRY_WAIT_SECONDS = int(os.environ.get("RETRY_WAIT_SECONDS", "20"))
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "3"))

AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
RUN_MODE = os.environ.get("RUN_MODE", "precheck_only").strip().lower()


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

    # Plain text token
    if not secret_val.startswith("{"):
        if not secret_val:
            raise Exception(json.dumps({
                "step": "load_token_from_secret",
                "secret_id": secret_id,
                "error": "token secret is empty"
            }))
        return secret_val

    # JSON token
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
    print("Using insecure TLS mode without CA")
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


def vault_request(method: str, addr: str, token: str, path: str, payload=None, ssl_context=None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}

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


def health(ssl_context, addr: str):
    st, data = vault_request("GET", addr, "", "sys/health", payload=None, ssl_context=ssl_context)
    return {"http": st, "data": data}


def dr_status(ssl_context, addr: str, token: str):
    st, payload = vault_get(ssl_context, addr, token, "sys/replication/dr/status")
    data = payload.get("data") or {}

    known_primary = data.get("known_primary_cluster_addrs") or []
    known_secondary = data.get("known_secondaries") or []

    return {
        "http": st,
        "mode": data.get("mode"),
        "state": data.get("state"),
        "connection_state": data.get("connection_state") or data.get("connection_status"),
        "primary_cluster_addr": data.get("primary_cluster_addr") or data.get("known_primary_cluster_addr"),
        "secondary_id": data.get("secondary_id"),
        "ssct_generation_counter": data.get("ssct_generation_counter"),
        "known_primary_cluster_addrs_count": len(known_primary),
        "known_primary_cluster_addrs_sample": known_primary[:2],
        "known_secondaries_count": len(known_secondary),
        "errors": payload.get("errors"),
        "raw_data": data
    }


def compact_mode(status_obj: dict):
    return (status_obj.get("raw_data") or {}).get("mode") or status_obj.get("mode")


def precheck(ssl_context, primary_token: str, secondary_token: str):
    print("Precheck: primary health")
    p_health = health(ssl_context, PRIMARY_ADDR)

    print("Precheck: secondary health")
    s_health = health(ssl_context, SECONDARY_ADDR)

    print("Precheck: primary DR status")
    p_status = dr_status(ssl_context, PRIMARY_ADDR, primary_token)

    print("Precheck: secondary DR status")
    s_status = dr_status(ssl_context, SECONDARY_ADDR, secondary_token)

    return {
        "primary_health": p_health,
        "secondary_health": s_health,
        "primary_dr_status": p_status,
        "secondary_dr_status": s_status
    }


def is_replication_already_established(checks: dict):
    p_mode = compact_mode(checks["primary_dr_status"])
    s_mode = compact_mode(checks["secondary_dr_status"])

    if checks["primary_dr_status"]["http"] == 200 and checks["secondary_dr_status"]["http"] == 200:
        if p_mode == "primary" and s_mode == "secondary":
            return True

    return False


def enable_dr_primary(ssl_context, primary_token: str):
    print("Step 1: Enable DR primary")
    st, data = vault_post(
        ssl_context,
        PRIMARY_ADDR,
        primary_token,
        "sys/replication/dr/primary/enable",
        payload={}
    )
    print(f"Step 1 HTTP status: {st}")
    require_ok("step1_enable_dr_primary", st, data, ok=(200, 204))

    print(f"Sleeping {POST_ENABLE_SLEEP_SECONDS}s after Step 1")
    time.sleep(POST_ENABLE_SLEEP_SECONDS)

    return {"http": st, "response": data}


def generate_secondary_public_key(ssl_context, secondary_token: str):
    print("Step 2: Generate secondary public key")
    st, data = vault_post(
        ssl_context,
        SECONDARY_ADDR,
        secondary_token,
        "sys/replication/dr/secondary/generate-public-key",
        payload={}
    )
    print(f"Step 2 HTTP status: {st}")
    require_ok("step2_generate_secondary_public_key", st, data, ok=(200, 204))

    pub = (data.get("data") or {}).get("secondary_public_key")
    if not pub:
        raise Exception(json.dumps({
            "step": "step2_generate_secondary_public_key",
            "error": "secondary_public_key missing",
            "response": data
        }))

    return pub


def generate_activation_token(ssl_context, primary_token: str, secondary_public_key: str):
    print("Step 3: Generate activation token")
    payload = {
        "secondary_public_key": secondary_public_key,
        "id": PRIMARY_CLUSTER_ID
    }

    st, data = vault_post(
        ssl_context,
        PRIMARY_ADDR,
        primary_token,
        "sys/replication/dr/primary/secondary-token",
        payload=payload
    )
    print(f"Step 3 HTTP status: {st}")
    require_ok("step3_generate_activation_token", st, data, ok=(200, 204))

    tok = (data.get("data") or {}).get("token")
    if not tok:
        raise Exception(json.dumps({
            "step": "step3_generate_activation_token",
            "error": "token missing",
            "response": data
        }))

    return tok


def enable_dr_secondary(ssl_context, secondary_token: str, activation_token: str):
    print("Step 4: Enable DR secondary")
    payload = {"token": activation_token}

    st, data = vault_post(
        ssl_context,
        SECONDARY_ADDR,
        secondary_token,
        "sys/replication/dr/secondary/enable",
        payload=payload
    )
    print(f"Step 4 HTTP status: {st}")
    require_ok("step4_enable_dr_secondary", st, data, ok=(200, 204))

    return {"http": st, "response": data}


def disable_dr_primary(ssl_context, primary_token: str):
    print("Cleanup: Disable DR primary before retry")
    st, data = vault_post(
        ssl_context,
        PRIMARY_ADDR,
        primary_token,
        "sys/replication/dr/primary/disable",
        payload={}
    )
    print(f"Cleanup disable primary HTTP status: {st}")
    require_ok("cleanup_disable_dr_primary", st, data, ok=(200, 204))
    return {"http": st, "response": data}


def single_attempt(ssl_context, primary_token: str, secondary_token: str):
    step1 = enable_dr_primary(ssl_context, primary_token)
    pub = generate_secondary_public_key(ssl_context, secondary_token)
    act_token = generate_activation_token(ssl_context, primary_token, pub)

    print(f"Sleeping {POST_TOKEN_SLEEP_SECONDS}s before Step 4")
    time.sleep(POST_TOKEN_SLEEP_SECONDS)

    step4 = enable_dr_secondary(ssl_context, secondary_token, act_token)

    return {
        "step1_enable_primary_http": step1["http"],
        "step2_secondary_public_key_prefix": pub[:12] + "...",
        "step3_activation_token_prefix": act_token[:12] + "...",
        "step4_enable_secondary_http": step4["http"]
    }


def run_enable_replication(precheck_only: bool = False):
    print("Loading Vault tokens from Secrets Manager")
    primary_token = load_token_from_secret(PRIMARY_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)
    secondary_token = load_token_from_secret(SECONDARY_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)

    print("Building SSL context")
    ssl_context = build_ssl_context()

    print("Running prechecks")
    checks = precheck(ssl_context, primary_token, secondary_token)

    if precheck_only:
        return {
            "statusCode": 200,
            "mode": "precheck_only",
            "checks": checks
        }

    if is_replication_already_established(checks):
        return {
            "statusCode": 200,
            "mode": "execute",
            "message": "DR replication is already established. No action required.",
            "checks": checks
        }

    attempt_errors = []

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"========== Attempt {attempt}/{MAX_ATTEMPTS} ==========")
        try:
            result = single_attempt(ssl_context, primary_token, secondary_token)

            verify_checks = precheck(ssl_context, primary_token, secondary_token)

            return {
                "statusCode": 200,
                "mode": "execute",
                "attempt": attempt,
                "primary_addr": PRIMARY_ADDR,
                "secondary_addr": SECONDARY_ADDR,
                "primary_cluster_id_used": PRIMARY_CLUSTER_ID,
                "initial_checks": checks,
                **result,
                "final_checks": verify_checks,
                "next_action": "Restart Vault on DR (Cluster B) nodes manually as per runbook."
            }

        except Exception as e:
            err = str(e)
            print(f"Attempt {attempt} failed: {err}")
            attempt_errors.append({
                "attempt": attempt,
                "error": err
            })

            try:
                disable_dr_primary(ssl_context, primary_token)
            except Exception as cleanup_err:
                print(f"Primary disable cleanup failed on attempt {attempt}: {cleanup_err}")
                attempt_errors.append({
                    "attempt": attempt,
                    "cleanup_primary_disable_error": str(cleanup_err)
                })

            if attempt < MAX_ATTEMPTS:
                print(f"Waiting {RETRY_WAIT_SECONDS}s before next retry")
                time.sleep(RETRY_WAIT_SECONDS)

    return {
        "statusCode": 500,
        "mode": "execute",
        "error": "All replication attempts failed",
        "initial_checks": checks,
        "attempts": attempt_errors
    }


if __name__ == "__main__":
    if RUN_MODE == "precheck_only":
        result = run_enable_replication(precheck_only=True)
    elif RUN_MODE == "execute":
        result = run_enable_replication(precheck_only=False)
    else:
        result = {
            "statusCode": 500,
            "error": f"Unsupported RUN_MODE: {RUN_MODE}"
        }

    print(json.dumps(result, indent=2))
    if result.get("statusCode") != 200:
        raise SystemExit(1)