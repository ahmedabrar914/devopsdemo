import os
import json
import urllib3
from urllib3.util.retry import Retry

# ----------------------------
# Env vars (required)
# ----------------------------
USW2_ADDR = os.environ["VAULT_USW2_ADDR"]       # https://usw2.dev.vault.corp.zscaler.com:8200
USE1_ADDR = os.environ["VAULT_USE1_ADDR"]       # https://use1.dev.vault.corp.zscaler.com:8200
USW2_TOKEN = os.environ["VAULT_USW2_TOKEN"]     # root token (for now)
USE1_TOKEN = os.environ["VAULT_USE1_TOKEN"]     # root token (for now)

# Optional TLS controls
VAULT_CA_BUNDLE = os.environ.get("VAULT_CA_BUNDLE")  # e.g. /opt/certs/corp-ca.pem
VAULT_SKIP_VERIFY = os.environ.get("VAULT_SKIP_VERIFY", "false").lower() == "true"


def build_http():
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )

    if VAULT_SKIP_VERIFY:
        return urllib3.PoolManager(retries=retries, cert_reqs="CERT_NONE")

    if VAULT_CA_BUNDLE:
        return urllib3.PoolManager(retries=retries, cert_reqs="CERT_REQUIRED", ca_certs=VAULT_CA_BUNDLE)

    return urllib3.PoolManager(retries=retries)


HTTP = build_http()


def _parse_json(resp):
    if not resp.data:
        return {}
    txt = resp.data.decode("utf-8", errors="replace").strip()
    if not txt:
        return {}
    return json.loads(txt)


def vault_get(addr: str, token: str, path: str):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {"X-Vault-Token": token}
    resp = HTTP.request(
        "GET",
        url,
        headers=headers,
        timeout=urllib3.Timeout(connect=5, read=15),
    )
    return resp.status, _parse_json(resp)


def summarize_health(status_code: int, health_json: dict):
    # sys/health returns useful keys at top level:
    # initialized, sealed, standby, version, cluster_name, cluster_id, etc.
    return {
        "http": status_code,
        "initialized": health_json.get("initialized"),
        "sealed": health_json.get("sealed"),
        "standby": health_json.get("standby"),
        "performance_standby": health_json.get("performance_standby"),
        "replication_performance_mode": health_json.get("replication_performance_mode"),
        "replication_dr_mode": health_json.get("replication_dr_mode"),
        "version": health_json.get("version"),
        "cluster_name": health_json.get("cluster_name"),
        "cluster_id": health_json.get("cluster_id"),
    }


def summarize_leader(status_code: int, leader_json: dict):
    data = leader_json.get("data") or leader_json
    return {
        "http": status_code,
        "ha_enabled": data.get("ha_enabled"),
        "is_self": data.get("is_self"),
        "leader_address": data.get("leader_address"),
        "leader_cluster_address": data.get("leader_cluster_address"),
    }


def summarize_replication(status_code: int, repl_json: dict):
    # replication/status shape:
    # { "data": { "dr": {...}, "performance": {...} } }
    data = repl_json.get("data") or {}
    dr = data.get("dr") or {}
    perf = data.get("performance") or {}
    return {
        "http": status_code,
        "dr_mode": dr.get("mode"),
        "dr_state": dr.get("state"),
        "dr_primary_cluster_addr": dr.get("primary_cluster_addr"),
        "perf_mode": perf.get("mode"),
        "perf_state": perf.get("state"),
    }


def check_cluster(name: str, addr: str, token: str):
    # 1) Health
    h_st, h_json = vault_get(addr, token, "sys/health")

    # 2) Leader
    l_st, l_json = vault_get(addr, token, "sys/leader")

    # 3) Replication status (optional but helpful)
    r_st, r_json = vault_get(addr, token, "sys/replication/status")

    return {
        "cluster": name,
        "addr": addr,
        "health": summarize_health(h_st, h_json),
        "leader": summarize_leader(l_st, l_json),
        "replication": summarize_replication(r_st, r_json),
        # Keep raw only if you want deeper debugging:
        # "raw": {"health": h_json, "leader": l_json, "replication": r_json},
    }


def lambda_handler(event, context):
    results = {
        "usw2": check_cluster("usw2", USW2_ADDR, USW2_TOKEN),
        "use1": check_cluster("use1", USE1_ADDR, USE1_TOKEN),
    }

    # Small convenience: infer "active" from sys/health standby flag
    for key in ["usw2", "use1"]:
        standby = results[key]["health"].get("standby")
        sealed = results[key]["health"].get("sealed")
        if sealed is True:
            role = "sealed"
        elif standby is True:
            role = "standby"
        elif standby is False:
            role = "active"
        else:
            role = "unknown"
        results[key]["inferred_role"] = role

    return {"statusCode": 200, "body": json.dumps(results, default=str)}