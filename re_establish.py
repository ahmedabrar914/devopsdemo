# re_establish_dr.py
import os
import json
import time
import random
import ssl
import boto3
import urllib3
from urllib3.util.retry import Retry

secrets = boto3.client("secretsmanager")

# Cluster A (to be secondary) and Cluster B (primary)
A_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
B_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

# PDF step-2 uses id=<cluster-b-region>
B_ID = os.environ["VAULT_SECONDARY_CLUSTER_ID"]

# ✅ Per your requirement: export Cluster A token in BOTH clusters
# In Lambda, this means: use this token in X-Vault-Token for ALL calls (A and B)
A_TOKEN_SECRET_ID = os.environ["VAULT_A_TOKEN_SECRET_ID"]
VAULT_TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "token")  # used only if secret is JSON

# DR operation/batch token used in PDF step-3
DR_OP_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]
DR_OP_JSON_KEY = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

# CA cert secrets
A_CA_SECRET_ID = os.environ["VAULT_PRIMARY_CA_SECRET_ID"]
B_CA_SECRET_ID = os.environ["VAULT_SECONDARY_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # optional

A_CA_PATH = "/tmp/vault-a-ca.pem"
B_CA_PATH = "/tmp/vault-b-ca.pem"

# waits
MIN_STEP_SLEEP = int(os.environ.get("MIN_STEP_SLEEP_SECONDS", "2"))
MAX_STEP_SLEEP = int(os.environ.get("MAX_STEP_SLEEP_SECONDS", "5"))
POST_UPDATE_SLEEP_SECONDS = int(os.environ.get("POST_UPDATE_SLEEP_SECONDS", "6"))


# ----------------------------
# Helpers: secrets / CA / http
# ----------------------------
def _load_secret_string(secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    if resp.get("SecretString"):
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")


def _extract_value(secret_id: str, json_key: str) -> str:
    """
    Supports:
      - plain string secrets: "hvs.xxxxx"
      - json secrets: {"token":"hvs.xxxxx"}
    """
    raw = _load_secret_string(secret_id).strip()
    if raw.startswith("{"):
        obj = json.loads(raw)
        val = (obj.get(json_key) or "").strip()
        if not val:
            raise Exception(f"Key '{json_key}' not found in secret {secret_id}")
        return val
    return raw


def _write_ca_to_tmp(secret_id: str, out_path: str) -> str:
    raw = _load_secret_string(secret_id).strip()
    pem = raw
    if VAULT_CA_SECRET_JSON_KEY:
        pem = json.loads(raw).get(VAULT_CA_SECRET_JSON_KEY)

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception(f"CA PEM invalid/missing in secret: {secret_id}")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(pem)
    return out_path


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
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=ca_file_path,
    )


def _sleep(label: str):
    s = random.randint(MIN_STEP_SLEEP, MAX_STEP_SLEEP)
    print(f"[wait] {label}: sleeping {s}s")
    time.sleep(s)


def _parse_json(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {"raw": txt}


def vault_get(http, addr: str, token: str, path: str):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = http.request("GET", url, headers=headers, timeout=urllib3.Timeout(connect=5, read=25))
    return resp.status, _parse_json(resp)


def vault_post(http, addr: str, token: str, path: str, payload=None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    body = json.dumps(payload or {}).encode("utf-8")
    resp = http.request("POST", url, headers=headers, body=body, timeout=urllib3.Timeout(connect=5, read=45))
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


def dr_status(http, addr: str, token: str):
    st, data = vault_get(http, addr, token, "sys/replication/dr/status")
    mode = ((data.get("data") or {}).get("mode"))
    state = ((data.get("data") or {}).get("state"))
    conn = ((data.get("data") or {}).get("connection_state")) or ((data.get("data") or {}).get("connection_status"))
    return {"http": st, "mode": mode, "state": state, "connection": conn, "raw": data}


# ----------------------------
# Main entry for router import
# ----------------------------
def run_re_establish_dr(event, context):
    """
    Implements PDF p51–52 (re-establish DR):
      PRE (only if needed): demote Cluster A if it's primary
      1) Cluster A: generate-public-key
      2) Cluster B: primary/secondary-token (id=<cluster-b-region>)
      3) Cluster A: secondary/update-primary (dr_operation_token + activation token)
      4) Verify status (both clusters)

    IMPORTANT per your requirement:
      - Uses Cluster A token for BOTH clusters (equivalent to exporting Cluster A VAULT_TOKEN everywhere)
    """
    event = event or {}

    if event.get("dry_run"):
        return {"statusCode": 200, "body": json.dumps({"message": "dry_run=true, not executing"})}

    # Load token (Cluster A token)
    token = _extract_value(A_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)

    # CA + HTTP clients
    _write_ca_to_tmp(A_CA_SECRET_ID, A_CA_PATH)
    _write_ca_to_tmp(B_CA_SECRET_ID, B_CA_PATH)
    http_a = build_http(A_CA_PATH)
    http_b = build_http(B_CA_PATH)

    # validate_only mode
    if event.get("validate_only"):
        out = {
            "mode": "re_establish_dr",
            "cluster_a_status": dr_status(http_a, A_ADDR, token),
            "cluster_b_status": dr_status(http_b, B_ADDR, token),
        }
        return {"statusCode": 200, "body": json.dumps(out, default=str)}

    steps = {}

    # Precheck A mode; demote only if A is primary
    a_stat = dr_status(http_a, A_ADDR, token)
    steps["precheck_cluster_a"] = a_stat

    if a_stat["http"] == 200 and a_stat["mode"] == "primary":
        st0, d0 = vault_post(http_a, A_ADDR, token, "sys/replication/dr/primary/demote", payload={})
        require_ok("p51_pre_demote_cluster_a", st0, d0)
        steps["p51_pre_demote_cluster_a"] = {"skipped": False, "http": st0}
        _sleep("after_demote")
    else:
        steps["p51_pre_demote_cluster_a"] = {"skipped": True, "reason": f"a_mode={a_stat.get('mode')}"}

    # Step 1: Cluster A generate-public-key
    st1, d1 = vault_post(http_a, A_ADDR, token, "sys/replication/dr/secondary/generate-public-key", payload={})
    require_ok("p51_step1_generate_public_key", st1, d1)

    pub = (d1.get("data") or {}).get("secondary_public_key")
    if not pub:
        raise Exception(json.dumps({"step": "p51_step1_generate_public_key", "error": "secondary_public_key missing", "response": d1}))
    steps["p51_step1_generate_public_key"] = {"http": st1, "secondary_public_key_prefix": pub[:12] + "..."}
    _sleep("after_public_key")

    # Step 2: Cluster B generate activation token
    st2, d2 = vault_post(
        http_b,
        B_ADDR,
        token,  # ✅ Cluster A token used on B per your requirement
        "sys/replication/dr/primary/secondary-token",
        payload={"secondary_public_key": pub, "id": B_ID},
    )
    require_ok("p51_step2_generate_activation_token", st2, d2)

    activation = (d2.get("data") or {}).get("token")
    if not activation:
        raise Exception(json.dumps({"step": "p51_step2_generate_activation_token", "error": "token missing", "response": d2}))
    steps["p51_step2_generate_activation_token"] = {"http": st2, "activation_token_prefix": activation[:12] + "..."}
    _sleep("after_activation_token")

    # Step 3: Cluster A update-primary (needs dr_operation_token)
    dr_op_token = _extract_value(DR_OP_SECRET_ID, DR_OP_JSON_KEY)

    st3, d3 = vault_post(
        http_a,
        A_ADDR,
        token,
        "sys/replication/dr/secondary/update-primary",
        payload={"dr_operation_token": dr_op_token, "token": activation},
    )
    require_ok("p52_step3_update_primary", st3, d3)
    steps["p52_step3_update_primary"] = {"http": st3, "response": d3}

    print(f"[wait] post_update: sleeping {POST_UPDATE_SLEEP_SECONDS}s")
    time.sleep(POST_UPDATE_SLEEP_SECONDS)
    _sleep("after_post_update")

    # Step 4: verify dr status
    steps["p52_step4_verify_a"] = dr_status(http_a, A_ADDR, token)
    _sleep("between_verify_a_b")
    steps["p52_step4_verify_b"] = dr_status(http_b, B_ADDR, token)

    out = {
        "mode": "re_establish_dr",
        "steps": steps,
        "expected": {"cluster_b_mode_should_be": "primary", "cluster_a_mode_should_be": "secondary"},
    }
    return {"statusCode": 200, "body": json.dumps(out, default=str)}