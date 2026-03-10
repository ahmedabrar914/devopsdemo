vault-init:
  stage: vault-init
  image: amazon/aws-cli:2.15.57

  parallel:
    matrix:
      - TARGET: "PRIMARY"
        AWS_REGION: "us-west-2"
        VAULT_TAG_NAME: "vaas-dev-primary"
        BASTION_INSTANCE_ID: "i-0957342a4e454e69e"
        SSH_KEY_PATH_ON_BASTION: "/usr/bin/vaas-dev-primary/vault-usw2-dev-ssh-key.pem"
        SSH_USER: "ubuntu"
        VAULT_ADDR_LOCAL: "https://usw2.dev.vault.corp.zscaler.com:8200"
        VAULT_CACERT_PATH: "/etc/vault.d/tls/ca.pem"
        ROOT_TOKEN_SECRET_NAME: "vaas/dev/primary/root-token"

      - TARGET: "DR"
        AWS_REGION: "us-east-1"
        VAULT_TAG_NAME: "vaas-dev-dr"
        BASTION_INSTANCE_ID: "i-076259481ae826b71"
        SSH_KEY_PATH_ON_BASTION: "/usr/bin/vaas-dev-dr/vault-dev-dr-ssh-key.pem"
        SSH_USER: "ubuntu"
        VAULT_ADDR_LOCAL: "https://use1.dev.vault.corp.zscaler.com:8200"
        VAULT_CACERT_PATH: "/etc/vault.d/tls/ca.pem"
        ROOT_TOKEN_SECRET_NAME: "vaas/dev/dr/root-token"

  variables:
    STAGE_ROLE_ARN: "arn:aws:iam::792014834907:role/gitlab-vaas-iac-role"
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
      echo "=== [$TARGET] Assuming role via OIDC ==="

      aws_sts_output="$(aws sts assume-role-with-web-identity \
        --role-arn "${STAGE_ROLE_ARN}" \
        --role-session-name "GitLabRunner-${CI_PROJECT_ID}-${CI_PIPELINE_ID}-${TARGET}" \
        --web-identity-token "${GITLAB_OIDC_TOKEN}" \
        --duration-seconds 3600 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text)"

      export AWS_ACCESS_KEY_ID="$(echo "$aws_sts_output" | awk '{print $1}')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$aws_sts_output" | awk '{print $2}')"
      export AWS_SESSION_TOKEN="$(echo "$aws_sts_output" | awk '{print $3}')"

      aws sts get-caller-identity

    - |
      echo "=== [$TARGET] Discovering Vault nodes ==="

      VAULT_NODE_IPS="$(
        aws ec2 describe-instances \
          --region "${AWS_REGION}" \
          --filters \
            "Name=tag:Name,Values=${VAULT_TAG_NAME}" \
            "Name=instance-state-name,Values=running" \
          --query 'Reservations[].Instances[].PrivateIpAddress' \
          --output text | tr '\t' '\n'
      )"

      if [ -z "${VAULT_NODE_IPS}" ]; then
        echo "No running Vault instances found for tag ${VAULT_TAG_NAME} in ${AWS_REGION}"
        exit 1
      fi

      echo "$VAULT_NODE_IPS"

      TARGET_VAULT_IP="$(echo "$VAULT_NODE_IPS" | head -n1)"

      if [ -z "${TARGET_VAULT_IP}" ]; then
        echo "Unable to determine target Vault IP"
        exit 1
      fi

      echo "Selected node: $TARGET_VAULT_IP"

    - |
      echo "=== [$TARGET] Sending SSM command ==="

      CMD_ID=$(aws ssm send-command \
        --region "$AWS_REGION" \
        --instance-ids "$BASTION_INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters commands="[
          \"set -euo pipefail\",
          \"echo Running on bastion: \$(hostname)\",
          \"echo Target Vault node: $TARGET_VAULT_IP\",
          \"STATUS=0\",
          \"STATUS_OUT=\$(ssh -i $SSH_KEY_PATH_ON_BASTION -o StrictHostKeyChecking=no $SSH_USER@$TARGET_VAULT_IP 'sudo -i bash -lc \\\"export VAULT_ADDR=$VAULT_ADDR_LOCAL; export VAULT_CACERT=$VAULT_CACERT_PATH; vault operator init -status\\\"' 2>&1) || STATUS=\$?\",
          \"echo \\\"\$STATUS_OUT\\\"\",
          \"if [ \\\"\$STATUS\\\" -eq 0 ]; then echo Vault already initialized; exit 0; fi\",
          \"if [ \\\"\$STATUS\\\" -ne 2 ]; then echo Unexpected vault status exit code \$STATUS; exit 1; fi\",
          \"echo Running vault initialization\",
          \"INIT_JSON=\$(ssh -i $SSH_KEY_PATH_ON_BASTION -o StrictHostKeyChecking=no $SSH_USER@$TARGET_VAULT_IP 'sudo -i bash -lc \\\"export VAULT_ADDR=$VAULT_ADDR_LOCAL; export VAULT_CACERT=$VAULT_CACERT_PATH; vault operator init -format=json\\\"')\",
          \"ROOT_TOKEN=\$(echo \\\"\$INIT_JSON\\\" | jq -r '.root_token')\",
          \"if [ -z \\\"\$ROOT_TOKEN\\\" ] || [ \\\"\$ROOT_TOKEN\\\" = \\\"null\\\" ]; then echo Failed to extract root token; exit 1; fi\",
          \"SECRET_PAYLOAD=\\\"{\\\\\\\"root_token\\\\\\\":\\\\\\\"\$ROOT_TOKEN\\\\\\\"}\\\"\",
          \"if aws secretsmanager describe-secret --region $AWS_REGION --secret-id $ROOT_TOKEN_SECRET_NAME >/dev/null 2>&1; then\",
          \"  echo Secret exists. Updating with new root token\",
          \"  aws secretsmanager put-secret-value --region $AWS_REGION --secret-id $ROOT_TOKEN_SECRET_NAME --secret-string \\\"\$SECRET_PAYLOAD\\\"\",
          \"else\",
          \"  echo Secret does not exist. Creating new secret\",
          \"  aws secretsmanager create-secret --region $AWS_REGION --name $ROOT_TOKEN_SECRET_NAME --secret-string \\\"\$SECRET_PAYLOAD\\\"\",
          \"fi\",
          \"echo Vault initialization complete and root token stored successfully\"
        ]" \
        --query "Command.CommandId" \
        --output text)

      echo "SSM Command ID: $CMD_ID"

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

        if [[ "$STATUS" == "Success" || "$STATUS" == "Failed" || "$STATUS" == "Cancelled" || "$STATUS" == "TimedOut" ]]; then
          break
        fi

        sleep 10
      done

      aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$CMD_ID" \
        --instance-id "$BASTION_INSTANCE_ID" \
        --query StandardOutputContent \
        --output text || true

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
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

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