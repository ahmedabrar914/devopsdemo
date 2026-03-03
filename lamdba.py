# lambda_function.py
import json

from enable_replication import run_enable_replication
from controlled_failover import run_controlled_failover
from re_establish_dr import run_re_establish_dr


def lambda_handler(event, context):
    """
    event:
      {
        "mode": "enable_replication" | "controlled_failover" | "re_establish_dr",
        "validate_only": true/false,
        "dry_run": true/false
      }
    """
    event = event or {}
    mode = event.get("mode")
    if not mode:
        return {"statusCode": 400, "body": json.dumps({"error": "Missing required field: mode"})}

    if mode == "enable_replication":
        return run_enable_replication(event, context)

    if mode == "controlled_failover":
        return run_controlled_failover(event, context)

    if mode == "re_establish_dr":
        return run_re_establish_dr(event, context)

    return {"statusCode": 400, "body": json.dumps({"error": f"Unknown mode: {mode}"})}