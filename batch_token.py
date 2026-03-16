import os
import json
import base64
import socket
import datetime
import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import boto3
import botocore
import urllib3
from urllib3.util.retry import Retry

# =========================================================
# LOGGING
# =========================================================
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

# =========================================================
# AWS CLIENTS
# =========================================================
secrets = boto3.client("secretsmanager")

# =========================================================
# ENVIRONMENT
# =========================================================
def get_required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


VAULT_ADDR = get_required_env("VAULT_PRIMARY_ADDR").rstrip("/")
VAULT_CA_SECRET_ID = get_required_env("VAULT_CA_SECRET_ID")
VAULT_ROOT_TOKEN_SECRET_ID = get_required_env("VAULT_ROOT_TOKEN_SECRET_ID")
ROTATED_TOKEN_SECRET_ID = get_required_env("ROTATED_TOKEN_SECRET_ID")

VAULT_ROOT_TOKEN_JSON_KEY = os.environ.get("VAULT_ROOT_TOKEN_JSON_KEY", "token").strip()
VAULT_CA_SECRET_JSON_KEY = os.environ.get("VAULT_CA_SECRET_JSON_KEY", "").strip()

POLICY_NAME = os.environ.get("POLICY_NAME", "dr-secondary-promotion").strip()
ROLE_NAME = os.environ.get("ROLE_NAME", "failover-handler").strip()
BATCH_TOKEN_TTL = os.environ.get("BATCH_TOKEN_TTL", "24h").strip()

HTTP_TIMEOUT_SECONDS = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "10"))
HTTP_CONNECT_TIMEOUT_SECONDS = float(os.environ.get("HTTP_CONNECT_TIMEOUT_SECONDS", "5"))
HTTP_MAX_RETRIES = int(os.environ.get("HTTP_MAX_RETRIES", "3"))

CA_PATH = "/tmp/vault-ca.pem"

# =========================================================
# CUSTOM EXCEPTIONS
# =========================================================
class AppError(Exception):
    def __init__(self, step: str, message: str, details: Optional[Dict[str, Any]] = None):
        self.step = step
        self.message = message
        self.details = details or {}
        super().__init__(self.__str__())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "message": self.message,
            "details": self.details,
        }

    def __str__(self) -> str:
        return json.dumps(self.to_dict())


# =========================================================
# HELPERS
# =========================================================
def mask_token(token: str) -> str:
    if not token:
        return "empty"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"


def utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_json_maybe(payload: str) -> Any:
    try:
        return json.loads(payload)
    except Exception:
        return payload


# =========================================================
# SECRET HELPERS
# =========================================================
def get_secret(secret_id: str) -> str:
    try:
        resp = secrets.get_secret_value(SecretId=secret_id)
    except botocore.exceptions.ClientError as e:
        raise AppError(
            step="get_secret",
            message=f"Unable to fetch secret: {secret_id}",
            details={"aws_error": str(e), "secret_id": secret_id},
        ) from e

    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]

    if "SecretBinary" in resp and resp["SecretBinary"]:
        try:
            return base64.b64decode(resp["SecretBinary"]).decode("utf-8")
        except Exception as e:
            raise AppError(
                step="decode_secret_binary",
                message=f"Unable to decode binary secret: {secret_id}",
                details={"secret_id": secret_id, "error": str(e)},
            ) from e

    raise AppError(
        step="get_secret",
        message=f"Secret is empty: {secret_id}",
        details={"secret_id": secret_id},
    )


def extract_value(secret_payload: str, json_key: Optional[str]) -> str:
    if not json_key:
        return secret_payload.strip()

    parsed = parse_json_maybe(secret_payload)
    if isinstance(parsed, dict):
        value = parsed.get(json_key)
        if value is None:
            raise AppError(
                step="extract_value",
                message=f"Key '{json_key}' not found in secret JSON",
                details={"json_key": json_key},
            )
        return str(value).strip()

    # fallback if payload is plain string
    return str(secret_payload).strip()


def load_root_token() -> str:
    payload = get_secret(VAULT_ROOT_TOKEN_SECRET_ID)
    token = extract_value(payload, VAULT_ROOT_TOKEN_JSON_KEY)
    if not token:
        raise AppError(
            step="load_root_token",
            message="Root token is empty after extraction",
            details={"secret_id": VAULT_ROOT_TOKEN_SECRET_ID},
        )
    logger.info("Loaded Vault root token successfully: %s", mask_token(token))
    return token


def load_ca_to_tmp() -> None:
    payload = get_secret(VAULT_CA_SECRET_ID)
    pem = extract_value(payload, VAULT_CA_SECRET_JSON_KEY)

    if "BEGIN CERTIFICATE" not in pem:
        raise AppError(
            step="load_ca_to_tmp",
            message="CA secret does not look like a PEM certificate",
            details={"secret_id": VAULT_CA_SECRET_ID},
        )

    try:
        with open(CA_PATH, "w", encoding="utf-8") as f:
            f.write(pem.strip() + "\n")
    except Exception as e:
        raise AppError(
            step="load_ca_to_tmp",
            message="Failed to write CA certificate to /tmp",
            details={"path": CA_PATH, "error": str(e)},
        ) from e

    if not os.path.exists(CA_PATH) or os.path.getsize(CA_PATH) == 0:
        raise AppError(
            step="load_ca_to_tmp",
            message="CA certificate file was not written correctly",
            details={"path": CA_PATH},
        )

    logger.info("Vault CA certificate loaded into %s", CA_PATH)


# =========================================================
# NETWORK / DNS VALIDATION
# =========================================================
def validate_vault_addr() -> Tuple[str, str]:
    parsed = urlparse(VAULT_ADDR)
    if parsed.scheme != "https":
        raise AppError(
            step="validate_vault_addr",
            message="Vault address must use https",
            details={"vault_addr": VAULT_ADDR},
        )

    if not parsed.hostname:
        raise AppError(
            step="validate_vault_addr",
            message="Vault address is missing hostname",
            details={"vault_addr": VAULT_ADDR},
        )

    host = parsed.hostname
    port = parsed.port or 443
    return host, str(port)


def check_dns_resolution(host: str) -> None:
    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise AppError(
            step="dns_resolution",
            message=f"DNS resolution failed for Vault host: {host}",
            details={"host": host, "error": str(e)},
        ) from e

    ip_list = sorted({item[4][0] for item in resolved if item and len(item) > 4})
    logger.info("Vault host %s resolved successfully: %s", host, ip_list)


# =========================================================
# HTTP CLIENT
# =========================================================
def build_http_client() -> urllib3.PoolManager:
    retry = Retry(
        total=HTTP_MAX_RETRIES,
        connect=HTTP_MAX_RETRIES,
        read=HTTP_MAX_RETRIES,
        redirect=0,
        status=HTTP_MAX_RETRIES,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST", "PUT"]),
        backoff_factor=1.0,
        raise_on_status=False,
    )

    timeout = urllib3.Timeout(
        connect=HTTP_CONNECT_TIMEOUT_SECONDS,
        read=HTTP_TIMEOUT_SECONDS,
    )

    return urllib3.PoolManager(
        cert_reqs="CERT_REQUIRED",
        ca_certs=CA_PATH,
        retries=retry,
        timeout=timeout,
    )


HTTP = None


def get_http() -> urllib3.PoolManager:
    global HTTP
    if HTTP is None:
        HTTP = build_http_client()
    return HTTP


# =========================================================
# VAULT API
# =========================================================
def vault_request(
    method: str,
    path: str,
    token: str,
    body: Optional[Dict[str, Any]] = None,
    expected_status: Optional[Tuple[int, ...]] = None,
) -> Tuple[int, Dict[str, Any]]:
    url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json",
    }

    encoded = None
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")

    try:
        resp = get_http().request(method, url, body=encoded, headers=headers)
    except Exception as e:
        raise AppError(
            step="vault_request",
            message="HTTP request to Vault failed",
            details={
                "method": method,
                "url": url,
                "error": str(e),
            },
        ) from e

    raw_text = resp.data.decode("utf-8") if resp.data else ""
    data: Dict[str, Any] = {}
    if raw_text:
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                data = parsed
            else:
                data = {"raw": parsed}
        except Exception:
            data = {"raw": raw_text}

    if expected_status and resp.status not in expected_status:
        raise AppError(
            step=f"vault_{method.lower()}_{path.replace('/', '_')}",
            message="Unexpected Vault response status",
            details={
                "http_status": resp.status,
                "expected_status": list(expected_status),
                "path": path,
                "response": data,
            },
        )

    return resp.status, data


def check_vault_health() -> Dict[str, Any]:
    # unauthenticated health check
    url = f"{VAULT_ADDR}/v1/sys/health?standbyok=true&perfstandbyok=true"
    try:
        resp = get_http().request("GET", url)
    except Exception as e:
        raise AppError(
            step="vault_health_check",
            message="Vault health endpoint is not reachable",
            details={"url": url, "error": str(e)},
        ) from e

    raw_text = resp.data.decode("utf-8") if resp.data else "{}"
    try:
        data = json.loads(raw_text)
    except Exception:
        data = {"raw": raw_text}

    # 200 active, 429 standby, 472 DR secondary, 473 performance standby
    if resp.status not in (200, 429, 472, 473):
        raise AppError(
            step="vault_health_check",
            message="Vault health check returned unexpected status",
            details={"http_status": resp.status, "response": data},
        )

    logger.info("Vault health check passed with status %s", resp.status)
    return {"http_status": resp.status, "response": data}


# =========================================================
# POLICY / ROLE
# =========================================================
POLICY_HCL = """
path "sys/replication/dr/secondary/promote" {
  capabilities = ["update"]
}

path "sys/replication/dr/secondary/update-primary" {
  capabilities = ["update"]
}

path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}
""".strip()


def ensure_policy(root_token: str) -> bool:
    status, _ = vault_request(
        "GET",
        f"sys/policies/acl/{POLICY_NAME}",
        root_token,
        expected_status=(200, 404),
    )

    if status == 200:
        logger.info("Policy already exists: %s", POLICY_NAME)
        return True

    _, _ = vault_request(
        "PUT",
        f"sys/policies/acl/{POLICY_NAME}",
        root_token,
        body={"policy": POLICY_HCL},
        expected_status=(200, 204, 204),
    )
    logger.info("Policy created successfully: %s", POLICY_NAME)
    return False


def ensure_role(root_token: str) -> bool:
    status, _ = vault_request(
        "GET",
        f"auth/token/roles/{ROLE_NAME}",
        root_token,
        expected_status=(200, 404),
    )

    if status == 200:
        logger.info("Token role already exists: %s", ROLE_NAME)
        return True

    body = {
        "allowed_policies": [POLICY_NAME],
        "orphan": True,
        "renewable": False,
        "token_type": "batch",
    }

    _, _ = vault_request(
        "POST",
        f"auth/token/roles/{ROLE_NAME}",
        root_token,
        body=body,
        expected_status=(200, 204),
    )
    logger.info("Token role created successfully: %s", ROLE_NAME)
    return False


# =========================================================
# CREATE BATCH TOKEN
# =========================================================
def create_batch_token(root_token: str) -> Tuple[str, str, int]:
    _, data = vault_request(
        "POST",
        f"auth/token/create/{ROLE_NAME}",
        root_token,
        body={"ttl": BATCH_TOKEN_TTL},
        expected_status=(200,),
    )

    auth = data.get("auth")
    if not auth:
        raise AppError(
            step="create_batch_token",
            message="Vault response missing auth block",
            details={"response": data},
        )

    client_token = auth.get("client_token")
    if not client_token:
        raise AppError(
            step="create_batch_token",
            message="Vault response missing client_token",
            details={"response": data},
        )

    accessor = auth.get("accessor", "n/a")
    lease_duration = int(auth.get("lease_duration", 0))

    logger.info(
        "Batch token created successfully. token=%s accessor=%s lease_duration=%s",
        mask_token(client_token),
        accessor,
        lease_duration,
    )
    return client_token, accessor, lease_duration


# =========================================================
# STORE TOKEN IN SECRETS MANAGER
# =========================================================
def store_rotated_token(token: str, accessor: str, ttl_seconds: int) -> str:
    created_at = utc_now()

    kv_payload = {
        "token": token,
        "token_accessor": accessor or "n/a",
        "token_duration": BATCH_TOKEN_TTL,
        "token_duration_seconds": ttl_seconds,
        "token_renewable": False,
        "token_type": "batch",
        "token_policies": ["default", POLICY_NAME],
        "identity_policies": [],
        "policies": ["default", POLICY_NAME],
        "policy_name": POLICY_NAME,
        "role_name": ROLE_NAME,
        "vault_addr": VAULT_ADDR,
        "created_at": created_at,
    }

    try:
        secrets.put_secret_value(
            SecretId=ROTATED_TOKEN_SECRET_ID,
            SecretString=json.dumps(kv_payload),
        )
    except botocore.exceptions.ClientError as e:
        raise AppError(
            step="store_rotated_token",
            message="Failed to store rotated token in Secrets Manager",
            details={"secret_id": ROTATED_TOKEN_SECRET_ID, "error": str(e)},
        ) from e

    logger.info("Rotated token stored successfully in secret: %s", ROTATED_TOKEN_SECRET_ID)
    return created_at


# =========================================================
# HANDLER
# =========================================================
def lambda_handler(event, context):
    try:
        logger.info("Lambda invocation started at %s", utc_now())
        logger.info("Event received: %s", json.dumps(event or {}))

        host, port = validate_vault_addr()
        logger.info("Validated Vault address. host=%s port=%s", host, port)

        load_ca_to_tmp()
        check_dns_resolution(host)
        health = check_vault_health()

        root_token = load_root_token()

        policy_existed = ensure_policy(root_token)
        role_existed = ensure_role(root_token)

        token, accessor, ttl_seconds = create_batch_token(root_token)
        created_at = store_rotated_token(token, accessor, ttl_seconds)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "DR batch token created and stored successfully",
                "vault_addr": VAULT_ADDR,
                "vault_health_status": health["http_status"],
                "policy_name": POLICY_NAME,
                "policy_existed": policy_existed,
                "role_name": ROLE_NAME,
                "role_existed": role_existed,
                "batch_token_ttl": BATCH_TOKEN_TTL,
                "token_prefix": token.split(".", 1)[0] if "." in token else token[:4],
                "created_at": created_at,
                "stored_in_secret": ROTATED_TOKEN_SECRET_ID,
            }),
        }

    except AppError as e:
        logger.error("Application error: %s", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": e.to_dict()
            }),
        }

    except Exception as e:
        logger.exception("Unhandled exception")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": {
                    "step": "unhandled_exception",
                    "message": str(e),
                }
            }),
        }