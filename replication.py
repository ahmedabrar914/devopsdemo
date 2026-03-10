import os
import json
import ssl
import subprocess
import urllib.request
import urllib.error

PRIMARY_ADDR = os.environ["VAULT_PRIMARY_ADDR"]
SECONDARY_ADDR = os.environ["VAULT_SECONDARY_ADDR"]

PRIMARY_TOKEN_SECRET_ID = os.environ["VAULT_PRIMARY_TOKEN_SECRET_ID"]
SECONDARY_TOKEN_SECRET_ID = os.environ["VAULT_SECONDARY_TOKEN_SECRET_ID"]
VAULT_TOKEN_JSON_KEY = os.environ.get("VAULT_TOKEN_JSON_KEY", "root_token")

VAULT_CA_SECRET_ID = os.environ["VAULT_CA_SECRET_ID"]
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY")

AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

CA_PATH = "/tmp/vault-ca.pem"


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

    try:
        resp = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise Exception(json.dumps({
            "step": "get_secret_value",
            "secret_id": secret_id,
            "error": "invalid JSON returned by aws cli",
            "details": str(exc),
            "stdout": stdout[:1000]
        }))

    if resp.get("SecretString"):
        return resp["SecretString"]

    if resp.get("SecretBinary"):
        return resp["SecretBinary"]

    raise Exception(json.dumps({
        "step": "get_secret_value",
        "secret_id": secret_id,
        "error": "secret does not contain SecretString or SecretBinary"
    }))


def load_token_from_secret(secret_id: str, json_key: str) -> str:
    secret_val = get_secret_value(secret_id)

    try:
        obj = json.loads(secret_val)
    except json.JSONDecodeError:
        raise Exception(json.dumps({
            "step": "load_token_from_secret",
            "secret_id": secret_id,
            "error": "token secret must be valid JSON"
        }))

    token = obj.get(json_key)
    if not token:
        raise Exception(json.dumps({
            "step": "load_token_from_secret",
            "secret_id": secret_id,
            "error": f"key '{json_key}' not found in token secret"
        }))

    return token


def load_ca_to_tmp() -> str:
    secret_val = get_secret_value(VAULT_CA_SECRET_ID)

    if VAULT_CA_SECRET_JSON_KEY:
        try:
            obj = json.loads(secret_val)
        except json.JSONDecodeError:
            raise Exception(json.dumps({
                "step": "load_ca_to_tmp",
                "secret_id": VAULT_CA_SECRET_ID,
                "error": "CA secret expected JSON but is not valid JSON"
            }))

        pem = obj.get(VAULT_CA_SECRET_JSON_KEY)
    else:
        pem = secret_val

    if not pem or "BEGIN CERTIFICATE" not in pem:
        raise Exception(json.dumps({
            "step": "load_ca_to_tmp",
            "secret_id": VAULT_CA_SECRET_ID,
            "error": "CA PEM not found or invalid in secret"
        }))

    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(pem)

    return CA_PATH


def build_ssl_context(ca_file_path: str):
    return ssl.create_default_context(cafile=ca_file_path)


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


def vault_get(addr: str, token: str, path: str, ssl_context):
    url = f"{addr.rstrip('/')}/v1/{path.lstrip('/')}"
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json"
    }

    req = urllib.request.Request(
        url=url,
        headers=headers,
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=20) as resp:
            return resp.getcode(), parse_json_bytes(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, parse_json_bytes(e.read())
    except urllib.error.URLError as e:
        return 0, {"error": f"URL error: {str(e.reason)}"}
    except Exception as e:
        return 0, {"error": f"Unexpected error: {str(e)}"}


def summarize_cluster(name: str, addr: str, token: str, ssl_context):
    result = {
        "cluster": name,
        "address": addr
    }

    health_status, health_data = vault_get(addr, token, "sys/health", ssl_context)
    result["health_http_status"] = health_status
    result["health_response"] = health_data

    dr_status, dr_data = vault_get(addr, token, "sys/replication/dr/status", ssl_context)
    result["dr_status_http_status"] = dr_status
    result["dr_status_response"] = dr_data

    # Small summary
    result["summary"] = {
        "reachable": health_status != 0,
        "token_valid_for_dr_status": dr_status not in (0, 403),
        "dr_mode": (dr_data.get("data") or {}).get("mode") if isinstance(dr_data, dict) else None,
        "dr_state": (dr_data.get("data") or {}).get("state") if isinstance(dr_data, dict) else None,
        "cluster_id": (dr_data.get("data") or {}).get("cluster_id") if isinstance(dr_data, dict) else None
    }

    return result


def main():
    try:
        print("Loading CA secret")
        ca_file = load_ca_to_tmp()

        print("Loading Vault tokens from Secrets Manager")
        primary_token = load_token_from_secret(PRIMARY_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)
        secondary_token = load_token_from_secret(SECONDARY_TOKEN_SECRET_ID, VAULT_TOKEN_JSON_KEY)

        print("Building SSL context")
        ssl_context = build_ssl_context(ca_file)

        print("Checking primary Vault")
        primary = summarize_cluster("primary", PRIMARY_ADDR, primary_token, ssl_context)

        print("Checking secondary Vault")
        secondary = summarize_cluster("secondary", SECONDARY_ADDR, secondary_token, ssl_context)

        result = {
            "statusCode": 200,
            "primary": primary,
            "secondary": secondary
        }

        print(json.dumps(result, indent=2))

    except Exception as e:
        result = {
            "statusCode": 500,
            "error": str(e)
        }
        print(json.dumps(result, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()