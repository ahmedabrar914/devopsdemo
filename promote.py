import os
import json
import time
import random
import ssl
import subprocess
import urllib.request
import urllib.error

A_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
B_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

B_ID = os.environ["VAULT_SECONDARY_CLUSTER_ID"]

A_TOKEN_SECRET_ID = os.environ["VAULT_PRIMARY_TOKEN_SECRET_ID"]
VAULT_TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "token")

DR_OP_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]
DR_OP_JSON_KEY = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

MIN_STEP_SLEEP = int(os.environ.get("MIN_STEP_SLEEP_SECONDS", "2"))
MAX_STEP_SLEEP = int(os.environ.get("MAX_STEP_SLEEP_SECONDS", "5"))
POST_UPDATE_SLEEP_SECONDS = int(os.environ.get("POST_UPDATE_SLEEP_SECONDS", "6"))

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


def extract_value(secret_id: str, json_key: str) -> str:
    raw = get_secret_value(secret_id).strip()

    # plain text secret
    if not raw.startswith("{"):
        if not raw:
            raise Exception(json.dumps({
                "step": "extract_value",
                "secret_id": secret_id,
                "error": "secret is empty"
            }))
        return raw

    # json secret
    obj = try_parse_json(raw)
    if obj is None or not isinstance(obj, dict):
        raise Exception(json.dumps({
            "step": "extract_value",
            "secret_id": secret_id,
            "error": "secret looks like JSON but could not be parsed"
        }))

    val = obj.get(json_key)
    if val:
        return str(val).strip()

    for key in ["token", "root_token", "vault_token", "dr_operation_token"]:
        if obj.get(key):
            return str(obj[key]).strip()

    raise Exception(json.dumps({
        "step": "extract_value",
        "secret_id": secret_id,
        "error": f"key not found in secret; tried '{json_key}', 'token', 'root_token', 'vault_token', 'dr_operation_token'"
    }))


def build_ssl_context():
    print("Using insecure TLS mode without CA for bastion/gitlab test")
    return ssl._create_unverified_context()


def sleep_step(label: str):
    s = random.randint(MIN_STEP_SLEEP, MAX_STEP_SLEEP)
    print(f"[wait] {label}: sleeping {s}s")
    time.sleep(s)


def parse_json_bytes(data: bytes):
    if not data:
        return {}
    txt = data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {"raw": txt}


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
        with urllib.request.urlopen(req, context=ssl_context, timeout=45) as resp:
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
    }


def run_re_establish_dr(validate_only: bool = False):
    print("Loading Cluster A token from Secrets Manager")
    token = extract_value(A_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)

    print("Building insecure SSL context")
    ssl_context = build_ssl_context()

    if validate_only:
        return {
            "statusCode": 200,
            "mode": "re_establish_dr_validate_only",
            "primary_addr": A_ADDR,
            "secondary_addr": B_ADDR,
            "secondary_cluster_id_used": B_ID,
            "cluster_a_status": dr_status(ssl_context, A_ADDR, token),
            "cluster_b_status": dr_status(ssl_context, B_ADDR, token),
        }

    # precheck A mode; demote only if A is primary
    a_stat = dr_status(ssl_context, A_ADDR, token)

    demote_skipped = True
    demote_reason = None

    if a_stat["http"] == 200 and a_stat["mode"] == "primary":
        print("Pre-step: Demoting Cluster A because it is primary")
        demote_skipped = False
        st0, d0 = vault_post(
            ssl_context,
            A_ADDR,
            token,
            "sys/replication/dr/primary/demote",
            payload={}
        )
        print(f"Pre-step demote HTTP status: {st0}")
        require_ok("step0_demote_cluster_a", st0, d0)
        sleep_step("after_demote")
    else:
        demote_reason = f"a_mode={a_stat.get('mode')}"
        print(f"Pre-step demote skipped: {demote_reason}")

    # step 1
    print("Step 1: Cluster A generate public key")
    st1, d1 = vault_post(
        ssl_context,
        A_ADDR,
        token,
        "sys/replication/dr/secondary/generate-public-key",
        payload={}
    )
    print(f"Step 1 HTTP status: {st1}")
    require_ok("step1_generate_public_key", st1, d1)

    pub = (d1.get("data") or {}).get("secondary_public_key")
    if not pub:
        raise Exception(json.dumps({
            "step": "step1_generate_public_key",
            "error": "secondary_public_key missing",
            "response": d1
        }))

    sleep_step("after_public_key")

    # step 2
    print("Step 2: Cluster B generate activation token")
    st2, d2 = vault_post(
        ssl_context,
        B_ADDR,
        token,
        "sys/replication/dr/primary/secondary-token",
        payload={"secondary_public_key": pub, "id": B_ID}
    )
    print(f"Step 2 HTTP status: {st2}")
    require_ok("step2_generate_activation_token", st2, d2)

    activation = (d2.get("data") or {}).get("token")
    if not activation:
        raise Exception(json.dumps({
            "step": "step2_generate_activation_token",
            "error": "token missing",
            "response": d2
        }))

    sleep_step("after_activation_token")

    # step 3
    print("Step 3: Cluster A update primary")
    dr_op_token = extract_value(DR_OP_SECRET_ID, DR_OP_JSON_KEY)

    st3, d3 = vault_post(
        ssl_context,
        A_ADDR,
        token,
        "sys/replication/dr/secondary/update-primary",
        payload={"dr_operation_token": dr_op_token, "token": activation}
    )
    print(f"Step 3 HTTP status: {st3}")
    require_ok("step3_update_primary", st3, d3)

    print(f"[wait] post_update: sleeping {POST_UPDATE_SLEEP_SECONDS}s")
    time.sleep(POST_UPDATE_SLEEP_SECONDS)
    sleep_step("after_post_update")

    # step 4 verify
    print("Step 4: Verify Cluster A")
    verify_a = dr_status(ssl_context, A_ADDR, token)

    sleep_step("between_verify_a_b")

    print("Step 5: Verify Cluster B")
    verify_b = dr_status(ssl_context, B_ADDR, token)

    return {
        "statusCode": 200,
        "mode": "re_establish_dr",
        "primary_addr": A_ADDR,
        "secondary_addr": B_ADDR,
        "secondary_cluster_id_used": B_ID,
        "precheck_cluster_a": a_stat,
        "step0_demote_skipped": demote_skipped,
        "step0_demote_reason": demote_reason,
        "step1_generate_public_key_http": st1,
        "step1_secondary_public_key_prefix": pub[:12] + "...",
        "step2_generate_activation_token_http": st2,
        "step2_activation_token_prefix": activation[:12] + "...",
        "step3_update_primary_http": st3,
        "verify_cluster_a": verify_a,
        "verify_cluster_b": verify_b,
        "expected": {
            "cluster_b_mode_should_be": "primary",
            "cluster_a_mode_should_be": "secondary",
        },
    }


if __name__ == "__main__":
    if RUN_MODE == "validate_only":
        result = run_re_establish_dr(validate_only=True)
    elif RUN_MODE == "execute":
        result = run_re_establish_dr(validate_only=False)
    else:
        result = {
            "statusCode": 500,
            "error": f"Unsupported RUN_MODE: {RUN_MODE}"
        }

    print(json.dumps(result, indent=2))
    if result.get("statusCode") != 200:
        raise SystemExit(1)