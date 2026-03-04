# re_establish_dr_clusterA_token_everywhere.py
import os, json, time, random, ssl
import boto3, urllib3
from urllib3.util.retry import Retry

secrets = boto3.client("secretsmanager")

A_ADDR = os.environ["VAULT_PRIMARY_ADDR"]          # Cluster A
B_ADDR = os.environ["VAULT_SECONDARY_ADDR"]        # Cluster B
B_ID   = os.environ["VAULT_SECONDARY_CLUSTER_ID"]  # PDF Step-2 id=<cluster-b-region>

# ✅ Use Cluster-A token everywhere (equivalent to "export VAULT_TOKEN=..." on both)
CLUSTER_A_TOKEN = os.environ["VAULT_CLUSTER_A_TOKEN"]

# DR operation/batch token for step-3
DR_OP_SECRET_ID = os.environ["FAILOVER_TOKEN_SECRET_ID"]
DR_OP_JSON_KEY  = os.environ.get("FAILOVER_TOKEN_JSON_KEY", "token")

# CA cert secrets
A_CA_SECRET_ID = os.environ["VAULT_PRIMARY_CA_SECRET_ID"]
B_CA_SECRET_ID = os.environ["VAULT_SECONDARY_CA_SECRET_ID"]
CA_JSON_KEY    = os.environ.get("VAULT_CA_SECRET_JSON_KEY")  # optional

A_CA_PATH = "/tmp/vault-a-ca.pem"
B_CA_PATH = "/tmp/vault-b-ca.pem"

MIN_SLEEP = int(os.environ.get("MIN_STEP_SLEEP_SECONDS", "2"))
MAX_SLEEP = int(os.environ.get("MAX_STEP_SLEEP_SECONDS", "5"))
POST_UPDATE_SLEEP = int(os.environ.get("POST_UPDATE_SLEEP_SECONDS", "6"))


def _sleep(label: str):
    s = random.randint(MIN_SLEEP, MAX_SLEEP)
    print(f"[wait] {label}: {s}s")
    time.sleep(s)

def _load_secret_string(secret_id: str) -> str:
    r = secrets.get_secret_value(SecretId=secret_id)
    return r["SecretString"] if r.get("SecretString") else r["SecretBinary"].decode("utf-8")

def _write_ca(secret_id: str, out_path: str):
    raw = _load_secret_string(secret_id).strip()
    pem = raw
    if CA_JSON_KEY:
        pem = json.loads(raw).get(CA_JSON_KEY)
    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception(f"CA PEM invalid/missing in secret: {secret_id}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(pem)

def _get_dr_op_token() -> str:
    raw = _load_secret_string(DR_OP_SECRET_ID).strip()
    if raw.startswith("{"):
        tok = (json.loads(raw).get(DR_OP_JSON_KEY) or "").strip()
        if not tok:
            raise Exception(f"'{DR_OP_JSON_KEY}' missing in {DR_OP_SECRET_ID}")
        return tok
    return raw

def build_http(ca_path: str):
    retries = Retry(
        total=3, backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    return urllib3.PoolManager(retries=retries, cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_path)

def _parse(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {"raw": txt}

def vget(http, addr, path):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    hdr = {"X-Vault-Token": CLUSTER_A_TOKEN}
    r = http.request("GET", url, headers=hdr, timeout=urllib3.Timeout(connect=5, read=25))
    return r.status, _parse(r)

def vpost(http, addr, path, payload=None):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    hdr = {"X-Vault-Token": CLUSTER_A_TOKEN, "Content-Type": "application/json"}
    body = json.dumps(payload or {}).encode("utf-8")
    r = http.request("POST", url, headers=hdr, body=body, timeout=urllib3.Timeout(connect=5, read=45))
    return r.status, _parse(r)

def require_ok(step, st, data, ok=(200, 204)):
    if st in ok:
        return
    raise Exception(json.dumps({
        "step": step,
        "http_status": st,
        "vault_errors": data.get("errors"),
        "response": data
    }, default=str))

def dr_status(http, addr):
    st, d = vget(http, addr, "sys/replication/dr/status")
    mode = (d.get("data") or {}).get("mode")
    state = (d.get("data") or {}).get("state")
    return {"http": st, "mode": mode, "state": state, "raw": d}

def lambda_handler(event, context):
    event = event or {}
    if event.get("dry_run"):
        return {"statusCode": 200, "message": "dry_run=true, not executing"}

    _write_ca(A_CA_SECRET_ID, A_CA_PATH)
    _write_ca(B_CA_SECRET_ID, B_CA_PATH)
    http_a = build_http(A_CA_PATH)
    http_b = build_http(B_CA_PATH)

    if event.get("validate_only"):
        return {"statusCode": 200, "a": dr_status(http_a, A_ADDR), "b": dr_status(http_b, B_ADDR)}

    steps = {}

    # Precheck: if A already secondary, do NOT demote (your earlier failure)
    a_stat = dr_status(http_a, A_ADDR)
    steps["precheck_a_status"] = a_stat

    if a_stat["http"] == 200 and a_stat["mode"] == "primary":
        st0, d0 = vpost(http_a, A_ADDR, "sys/replication/dr/primary/demote", {})
        require_ok("p51_pre_demote_cluster_a", st0, d0)
        steps["p51_pre_demote_cluster_a"] = {"skipped": False, "http": st0}
        _sleep("after_demote")
    else:
        steps["p51_pre_demote_cluster_a"] = {"skipped": True, "reason": f"a_mode={a_stat['mode']}"}

    # Step 1 (PDF p51): generate public key on A
    st1, d1 = vpost(http_a, A_ADDR, "sys/replication/dr/secondary/generate-public-key", {})
    require_ok("p51_step1_generate_public_key", st1, d1)
    pub = (d1.get("data") or {}).get("secondary_public_key")
    if not pub:
        raise Exception(json.dumps({"step": "p51_step1_generate_public_key", "error": "secondary_public_key missing", "response": d1}))
    steps["p51_step1_generate_public_key"] = {"http": st1, "secondary_public_key_prefix": pub[:12] + "..."}
    _sleep("after_public_key")

    # Step 2 (PDF p51): activation token on B (still using Cluster-A token by your requirement)
    st2, d2 = vpost(
        http_b, B_ADDR,
        "sys/replication/dr/primary/secondary-token",
        {"secondary_public_key": pub, "id": B_ID},
    )
    require_ok("p51_step2_generate_activation_token_on_b", st2, d2)
    activation = (d2.get("data") or {}).get("token")
    if not activation:
        raise Exception(json.dumps({"step": "p51_step2_generate_activation_token_on_b", "error": "token missing", "response": d2}))
    steps["p51_step2_generate_activation_token_on_b"] = {"http": st2, "activation_token_prefix": activation[:12] + "..."}
    _sleep("after_activation_token")

    # Step 3 (PDF p52): update-primary on A using dr_operation_token + activation token
    dr_op = _get_dr_op_token()
    st3, d3 = vpost(
        http_a, A_ADDR,
        "sys/replication/dr/secondary/update-primary",
        {"dr_operation_token": dr_op, "token": activation},
    )
    require_ok("p52_step3_update_primary_on_a", st3, d3)
    steps["p52_step3_update_primary_on_a"] = {"http": st3, "response": d3}

    time.sleep(POST_UPDATE_SLEEP)
    _sleep("after_post_update_sleep")

    # Step 4 (PDF p52): verify status on both
    steps["p52_step4_verify_a"] = dr_status(http_a, A_ADDR)
    _sleep("between_verify_a_b")
    steps["p52_step4_verify_b"] = dr_status(http_b, B_ADDR)

    return {
        "statusCode": 200,
        "mode": "re_establish_dr",
        "steps": steps,
        "expected": {"cluster_b_mode_should_be": "primary", "cluster_a_mode_should_be": "secondary"},
    }