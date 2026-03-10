dev-dr-replication:
  stage: dev-dr-replication
  image: amazon/aws-cli:2.15.57

  variables:
    STAGE_ROLE_ARN: "arn:aws:iam::792014834907:role/gitlab-vaas-iac-role"
    AWS_REGION: "us-west-2"
    BASTION_INSTANCE_ID: "i-0957342a4e454e69e"

    VAULT_PRIMARY_ADDR: "https://usw2.dev.vault.corp.zscaler.com:8200"
    VAULT_SECONDARY_ADDR: "https://use1.dev.vault.corp.zscaler.com:8200"

    VAULT_PRIMARY_TOKEN_SECRET_ID: "vaas/dev/primary/root-token"
    VAULT_SECONDARY_TOKEN_SECRET_ID: "vaas/dev/dr/root-token"
    VAULT_TOKEN_JSON_KEY: "root_token"

    VAULT_PRIMARY_CLUSTER_ID: "usw2"
    POST_ENABLE_SLEEP_SECONDS: "8"

    KUBERNETES_POD_LABELS_INTERNET_ALLOW: "internet=allow"

  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.corp.zscaler.com

  before_script:
    - set -euo pipefail
    - yum -y install bash coreutils jq >/dev/null 2>&1 || true
    - aws --version

  script:
    - |
      echo "=== Assuming role via OIDC ==="

      aws_sts_output="$(aws sts assume-role-with-web-identity \
        --role-arn "${STAGE_ROLE_ARN}" \
        --role-session-name "GitLabRunner-${CI_PROJECT_ID}-${CI_PIPELINE_ID}-dr-replication" \
        --web-identity-token "${GITLAB_OIDC_TOKEN}" \
        --duration-seconds 3600 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text)"

      export AWS_ACCESS_KEY_ID="$(echo "$aws_sts_output" | awk '{print $1}')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$aws_sts_output" | awk '{print $2}')"
      export AWS_SESSION_TOKEN="$(echo "$aws_sts_output" | awk '{print $3}')"

      aws sts get-caller-identity

    - |
      echo "=== Encoding replication script ==="
      SCRIPT_B64="$(base64 -w 0 scripts/dr_replication_no_ca.py)"
      export SCRIPT_B64

    - |
      echo "=== Sending SSM command to bastion ==="

      CMD_ID=$(aws ssm send-command \
        --region "$AWS_REGION" \
        --instance-ids "$BASTION_INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters commands="[
          \"set -euo pipefail\",
          \"echo Running on bastion: \$(hostname)\",
          \"mkdir -p /tmp/vault-dr-replication\",
          \"cd /tmp/vault-dr-replication\",
          \"cat <<'EOF' | base64 -d > dr_replication_no_ca.py\",
          \"$SCRIPT_B64\",
          \"EOF\",
          \"chmod 700 dr_replication_no_ca.py\",
          \"export AWS_REGION='$AWS_REGION'\",
          \"export VAULT_PRIMARY_ADDR='$VAULT_PRIMARY_ADDR'\",
          \"export VAULT_SECONDARY_ADDR='$VAULT_SECONDARY_ADDR'\",
          \"export VAULT_PRIMARY_TOKEN_SECRET_ID='$VAULT_PRIMARY_TOKEN_SECRET_ID'\",
          \"export VAULT_SECONDARY_TOKEN_SECRET_ID='$VAULT_SECONDARY_TOKEN_SECRET_ID'\",
          \"export VAULT_TOKEN_JSON_KEY='$VAULT_TOKEN_JSON_KEY'\",
          \"export VAULT_PRIMARY_CLUSTER_ID='$VAULT_PRIMARY_CLUSTER_ID'\",
          \"export POST_ENABLE_SLEEP_SECONDS='$POST_ENABLE_SLEEP_SECONDS'\",
          \"python3 dr_replication_no_ca.py\"
        ]" \
        --query "Command.CommandId" \
        --output text)

      echo "SSM Command ID: $CMD_ID"
      export CMD_ID

    - |
      echo "=== Waiting for SSM execution ==="

      STATUS=""

      for i in $(seq 1 60); do
        STATUS=$(aws ssm get-command-invocation \
          --region "$AWS_REGION" \
          --command-id "$CMD_ID" \
          --instance-id "$BASTION_INSTANCE_ID" \
          --query Status \
          --output text 2>/dev/null || true)

        echo "Poll $i: Status=$STATUS"

        if [[ "$STATUS" == "Success" || "$STATUS" == "Failed" || "$STATUS" == "TimedOut" || "$STATUS" == "Cancelled" ]]; then
          break
        fi

        sleep 10
      done

      echo "=== SSM STDOUT ==="
      aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$CMD_ID" \
        --instance-id "$BASTION_INSTANCE_ID" \
        --query StandardOutputContent \
        --output text || true

      echo "=== SSM STDERR ==="
      aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$CMD_ID" \
        --instance-id "$BASTION_INSTANCE_ID" \
        --query StandardErrorContent \
        --output text || true

      if [ "$STATUS" != "Success" ]; then
        echo "SSM execution failed"
        exit 1
      fi

  needs:
    - dev-primary-peering-apply

  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      when: manual
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      when: manual