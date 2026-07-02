#! /bin/bash
set -xeuo pipefail

LOGFILE="/var/log/vault-cloud-init.log"
SYSTEMD_DIR="${systemd_dir}"
VAULT_DIR_CONFIG="${vault_dir_config}"
VAULT_DIR_TLS="${vault_dir_config}/tls"
VAULT_DIR_DATA="${vault_dir_home}/data"
VAULT_DIR_LICENSE="${vault_dir_home}/license"
VAULT_DIR_PLUGINS="${vault_dir_home}/plugins"
VAULT_DIR_LOGS="${vault_dir_logs}"
VAULT_DIR_BIN="${vault_dir_bin}"
VAULT_USER="${vault_user_name}"
VAULT_GROUP="${vault_group_name}"
VAULT_INSTALL_URL="${vault_install_url}"
REQUIRED_PACKAGES="unzip"
ADDITIONAL_PACKAGES="${additional_package_names}"
# --- ZOTEL / OTel Agent settings ---
ZOTEL_INSTALL_DIR="${zotel_install_dir}"
ZOTEL_INSTALLER_S3_URI="${zotel_installer_s3_uri}"
ZOTEL_METADATA_JSON_S3_URI="${zotel_metadata_json_s3_uri}"
ZOTEL_INSTALLER_NAME="${zotel_installer_name}"
ZOTEL_METADATA_JSON_FILE_NAME="${zotel_metadata_json_file_name}"
ZOTEL_SERVICE_GROUP="${zotel_service_group}"
ZOTEL_INGEST_HOST="${zotel_ingest_host}"
ZOTEL_INGEST_TOKEN="${zotel_ingest_token}"
ZOTEL_SIEM_ENABLED="${zotel_siem_enabled}"
ZOTEL_SIEM_LOGS_ENDPOINT="${zotel_siem_logs_endpoint}"
ZOTEL_SIEM_KEY="${zotel_siem_key}"
ZOTEL_SIEM_SECRET="${zotel_siem_secret}"

# --- vault-watchdog-node settings ---
WATCHDOG_BINARY_S3_URI="${watchdog_binary_s3_uri}"
WATCHDOG_BINARY_NAME="${watchdog_binary_name}"
WATCHDOG_CHECKS_CONFIG_S3_URI="${watchdog_checks_config_s3_uri}"
WATCHDOG_INSTALL_DIR="${watchdog_install_dir}"
WATCHDOG_CONFIG_DIR="${watchdog_config_dir}"
WATCHDOG_DATA_DIR="${watchdog_data_dir}"
WATCHDOG_LOG_DIR="${watchdog_log_dir}"
WATCHDOG_EVIDENCE_DIR="${watchdog_data_dir}/evidence"
WATCHDOG_USER="${watchdog_user_name}"
WATCHDOG_GROUP="${watchdog_group_name}"
WATCHDOG_RUN_INTERVAL="${watchdog_run_interval}"
WATCHDOG_VAULT_TOKEN_FILE="${watchdog_vault_token_file}"
WATCHDOG_VAULT_TOKEN="${watchdog_vault_token}"
WATCHDOG_VAULT_ADDR="${watchdog_vault_addr}"
WATCHDOG_VAULT_CLUSTER_ADDR="${watchdog_vault_cluster_addr}"

ROLE_CONFIG="/sc/zotelagent/conf/role-config.yaml"

function log {
  local level="$1"
  local message="$2"
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local log_entry="$timestamp [$level] - $message"

  echo "$log_entry" | tee -a "$LOGFILE"
}

function detect_os_distro {
  local OS_DISTRO_NAME=$(grep "^NAME=" /etc/os-release | cut -d"\"" -f2)
  local OS_DISTRO_DETECTED

  case "$OS_DISTRO_NAME" in
    "Ubuntu"*)
      OS_DISTRO_DETECTED="ubuntu"
      ;;
    "CentOS Linux"*)
      OS_DISTRO_DETECTED="centos"
      ;;
    "Red Hat"*)
      OS_DISTRO_DETECTED="rhel"
      ;;
    "Amazon Linux"*)
      OS_DISTRO_DETECTED="amzn2023"
      ;;
    *)
      log "ERROR" "'$OS_DISTRO_NAME' is not a supported Linux OS distro for Vault."
      exit_script 1
  esac

  echo "$OS_DISTRO_DETECTED"
}

function install_aws_cli() {
  local os_distro="$1"

  if [[ -n "$(command -v aws)" ]]; then
    log "INFO" "Detected 'aws' (awscli) is already installed. Skipping."
  else
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    ./aws/install
    rm -f ./awscliv2.zip && rm -rf ./aws
  fi
}

function install_packages() {
  local os_distro="$1"

  if [[ "$os_distro" == "ubuntu" ]]; then
    apt-get update -y
    apt-get install -y $REQUIRED_PACKAGES $ADDITIONAL_PACKAGES
  elif [[ "$OS_DISTRO" == "centos" || "$OS_DISTRO" == "rhel" || "$OS_DISTRO" == "amzn2023" ]]; then
    yum install -y $REQUIRED_PACKAGES $ADDITIONAL_PACKAGES
  else
    log "ERROR" "Unable to determine package manager"
  fi
}

function scrape_vm_info {
  echo "[INFO] Scraping virtual machine information..."

  # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
  IMDSV2_TOKEN="$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 240" "http://169.254.169.254/latest/api/token")"
  INSTANCE_ID="$(curl -s -H "X-aws-ec2-metadata-token: $IMDSV2_TOKEN" http://169.254.169.254/latest/meta-data/instance-id)"
  REGION="$(curl -s -H "X-aws-ec2-metadata-token: $IMDSV2_TOKEN" http://169.254.169.254/latest/meta-data/placement/region)"
  AVAILABILITY_ZONE="$(curl -s -H "X-aws-ec2-metadata-token: $IMDSV2_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)"

  echo "[INFO] Done scraping virtual machine information."
}

# user_create creates a dedicated linux user for Vault
function user_group_create {
  # Create the dedicated as a system group
  sudo groupadd --system $VAULT_GROUP

  # Create a dedicated user as a system user
  sudo useradd --system -m -d $VAULT_DIR_CONFIG -g $VAULT_GROUP $VAULT_USER
  sudo usermod -s /sbin/nologin $VAULT_USER
}

# directory_creates creates the necessary directories for Vault
function directory_create {
  # Define all directories needed as an array
  directories=( $VAULT_DIR_CONFIG $VAULT_DIR_DATA $VAULT_DIR_PLUGINS $VAULT_DIR_TLS $VAULT_DIR_LICENSE $VAULT_DIR_LOGS )

  # Loop through each item in the array; create the directory and configure permissions
  for directory in "$${directories[@]}"; do
    mkdir -p $directory
    sudo chown $VAULT_USER:$VAULT_GROUP $directory
    sudo chmod 750 $directory
  done
}

# install_vault_binary downloads the Vault binary and puts it in dedicated bin directory
function install_vault_binary {
  log "INFO" "Downloading Vault Enterprise binary"
  sudo curl -so $VAULT_DIR_BIN/vault.zip $VAULT_INSTALL_URL

  log "INFO" "Unzipping Vault Enterprise binary to $VAULT_DIR_BIN"
  sudo unzip $VAULT_DIR_BIN/vault.zip vault -d $VAULT_DIR_BIN
  sudo unzip $VAULT_DIR_BIN/vault.zip -x vault -d $VAULT_DIR_LICENSE

  sudo rm $VAULT_DIR_BIN/vault.zip
}

function install_vault_plugins {
  %{ for p in vault_plugin_urls ~}
  sudo curl -s --output-dir $VAULT_DIR_PLUGINS -O ${p}
  sudo unzip -o $VAULT_DIR_PLUGINS/$(basename ${p}) -d $VAULT_DIR_PLUGINS
  rm $VAULT_DIR_PLUGINS/$(basename ${p})
  chown 0700 $VAULT_DIR_PLUGINS/$(basename ${p} | cut -d '_' -f 1)
  %{ endfor ~}

  chmod 0700 $VAULT_DIR_PLUGINS
  sudo chown -R $VAULT_USER:$VAULT_GROUP $VAULT_DIR_PLUGINS
}

# fetch_tls_certificates fetches the TLS certificates from cloud's secret manager
function fetch_tls_certificates {
  log "INFO" "Retrieving TLS certificates '${sm_vault_tls_cert_arn}' from Secrets Manager."
  aws secretsmanager get-secret-value --secret-id ${sm_vault_tls_cert_arn} --region $REGION --output text --query SecretString > $VAULT_DIR_TLS/cert.pem

  log "INFO" "Retrieving TLS private key '${sm_vault_tls_cert_key_arn}' from Secrets Manager."
  aws secretsmanager get-secret-value --secret-id ${sm_vault_tls_cert_key_arn} --region $REGION --output text --query SecretString > $VAULT_DIR_TLS/key.pem

  %{ if sm_vault_tls_ca_bundle != "NONE" ~}
  log "INFO" "Retrieving CA certificate '${sm_vault_tls_ca_bundle}' from Secrets Manager."
  aws secretsmanager get-secret-value --secret-id ${sm_vault_tls_ca_bundle} --region $REGION --output text --query SecretString > $VAULT_DIR_TLS/ca.pem
  %{ endif ~}

  log "INFO" "Setting certificate file permissions and ownership"
  sudo chown $VAULT_USER:$VAULT_GROUP $VAULT_DIR_TLS/*
  sudo chmod 400 $VAULT_DIR_TLS/*
}

function fetch_vault_license {
  log "INFO" "Retrieving Vault license '${sm_vault_license_arn}' from Secrets Manager."
  aws secretsmanager get-secret-value --secret-id ${sm_vault_license_arn} --region $REGION --output text --query SecretString > $VAULT_DIR_LICENSE/license.hclic

  log "INFO" "Setting license file permissions and ownership"
  sudo chown $VAULT_USER:$VAULT_GROUP $VAULT_DIR_LICENSE/license.hclic
  sudo chmod 660 $VAULT_DIR_LICENSE/license.hclic
}

function generate_vault_config {
  FULL_HOSTNAME="$(hostname -f)"

  sudo bash -c "cat > $VAULT_DIR_CONFIG/server.hcl" <<EOF
disable_mlock = ${vault_disable_mlock}
ui            = ${vault_enable_ui}

default_lease_ttl = "${vault_default_lease_ttl_duration}"
max_lease_ttl     = "${vault_max_lease_ttl_duration}"

listener "tcp" {
  address       = "[::]:${vault_port_api}"
  tls_cert_file = "$VAULT_DIR_TLS/cert.pem"
  tls_key_file  = "$VAULT_DIR_TLS/key.pem"

  tls_require_and_verify_client_cert = ${vault_tls_require_and_verify_client_cert}
  tls_disable_client_certs           = ${vault_tls_disable_client_certs}
  telemetry {
    unauthenticated_metrics_access = true
  }
}

storage "raft" {
  path                   = "$VAULT_DIR_DATA"
  node_id                = "$INSTANCE_ID"
  performance_multiplier = ${vault_raft_performance_multiplier}

  autopilot_redundancy_zone = "$AVAILABILITY_ZONE"

  retry_join {
    auto_join        = "provider=aws region=$REGION tag_key=${auto_join_tag_key} tag_value=${auto_join_tag_value} addr_type=private_v4"
    auto_join_scheme = "https"
%{ if sm_vault_tls_ca_bundle != "NONE" ~}
    leader_ca_cert_file   = "$VAULT_DIR_TLS/ca.pem"
%{ endif ~}
%{ if vault_fqdn != "" ~}
    leader_tls_servername = "${vault_fqdn}"
%{ else ~}
    leader_tls_servername = "$FULL_HOSTNAME"
%{ endif ~}
  }
}

telemetry {
  prometheus_retention_time = "30m"
  disable_hostname = true
}

license_path = "$VAULT_DIR_LICENSE/license.hclic"

audit {
  file      = "file"
  file_path = "/var/log/vault/vault-audit.log"
  log_raw   = false
  mode      = "0640"
}

%{ if vault_seal_type == "awskms" ~}
seal "awskms" {
%{ for key, value in vault_seal_attributes ~}
  ${key} = "${value}"
%{ endfor ~}
}
%{ endif ~}

api_addr      = "https://$FULL_HOSTNAME:${vault_port_api}"
cluster_addr  = "https://$FULL_HOSTNAME:${vault_port_cluster}"

plugin_directory = "$VAULT_DIR_PLUGINS"
%{ if length(vault_telemetry_config) > 0 ~}
telemetry {
%{ for key, value in vault_telemetry_config ~}
  ${key} = "${value}"
%{ endfor ~}
}
%{ endif ~}
EOF

  log "INFO" "Setting Vault server config file permissions and ownership"
  sudo chmod 600 $VAULT_DIR_CONFIG/server.hcl
  sudo chown $VAULT_USER:$VAULT_GROUP $VAULT_DIR_CONFIG/server.hcl
}

function install_zotelagent {
  log "INFO" "Installing zotelagent into $ZOTEL_INSTALL_DIR"

  sudo mkdir -p "$ZOTEL_INSTALL_DIR"
  cd "$ZOTEL_INSTALL_DIR"

  log "INFO" "Downloading installer: $ZOTEL_INSTALLER_S3_URI"
  aws s3 cp "$ZOTEL_INSTALLER_S3_URI" "./$ZOTEL_INSTALLER_NAME"
  sudo chmod +x "./$ZOTEL_INSTALLER_NAME"

  log "INFO" "Downloading zotel metadata json: $ZOTEL_METADATA_JSON_S3_URI"
  aws s3 cp "$ZOTEL_METADATA_JSON_S3_URI" "./$ZOTEL_METADATA_JSON_FILE_NAME"
  sudo chmod +x "./$ZOTEL_METADATA_JSON_FILE_NAME"

  log "INFO" "Running zotel installer with metadata json"
  sudo env \
    ZOTELAGENT_INSTALL_PATH="$ZOTEL_INSTALL_DIR" \
    SERVICE_GROUP="$ZOTEL_SERVICE_GROUP" \
    ZOTEL_SIEM_ENABLED="$ZOTEL_SIEM_ENABLED" \
    ZOTEL_SIEM_LOGS_ENDPOINT="$ZOTEL_SIEM_LOGS_ENDPOINT" \
    ZOTEL_SIEM_KEY="$ZOTEL_SIEM_KEY" \
    ZOTEL_SIEM_SECRET="$ZOTEL_SIEM_SECRET" \
    "./$ZOTEL_INSTALLER_NAME" install -d "$ZOTEL_INGEST_HOST" -t "$ZOTEL_INGEST_TOKEN" -c "$ZOTEL_METADATA_JSON_FILE_NAME"
}

function configure_zotel_vault_metrics {
  log "INFO" "Configuring zotel prometheus scrape config for Vault"

  sudo tee "$ZOTEL_INSTALL_DIR/zotelagent/conf/prometheus_simple_config.yaml" >/dev/null <<EOF
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: 'vault'
          metrics_path: '/v1/sys/metrics'
          params:
            format: ['prometheus']
          static_configs:
            - targets: ['127.0.0.1:8200']
          scheme: 'https'
          tls_config:
            insecure_skip_verify: true

service:
  pipelines:
    metrics/p1:
      receivers: [prometheus]
      processors: [memory_limiter,resourcedetection,resource,batch]
      exporters: [otlphttp/kfuse]
EOF
}

function configure_vault_server_logging {
  log "INFO" "Configuring Vault server logs from journald to /var/log/vault/vault-journalctl.log"

  sudo tee /etc/rsyslog.d/10-vault-journal.conf >/dev/null <<'EOF'
  module(load="imjournal" StateFile="imjournal-vault.state")

  if ($syslogtag startswith "vault" and ($msg contains "[WARN]" or $msg contains "[ERROR]" or $msg contains "failed")) then {
    action(type="omfile" file="/var/log/vault/vault-journalctl.log")
    stop
  }
EOF

  # Server log: rsyslog writes this
  if [ ! -f /var/log/vault/vault-journalctl.log ]; then
    sudo install -m 664 -o syslog -g "$VAULT_GROUP" /dev/null /var/log/vault/vault-journalctl.log || true
  else
    sudo chown syslog:"$VAULT_GROUP" /var/log/vault/vault-journalctl.log || true
    sudo chmod 664 /var/log/vault/vault-journalctl.log || true
  fi

  sudo tee /etc/rsyslog.d/10-vault-syslog-filter.conf >/dev/null <<'EOF'
  if ($msg contains "[INFO]") then {
  stop
  }
EOF
}

function patch_zotel_role_config {
  log "INFO" "Patching Zotel role-config"
  if [ ! -f "$ROLE_CONFIG" ]; then
    log "WARN" "$ROLE_CONFIG not found, skipping patch"
    return 0
  fi
  sudo cp "$ROLE_CONFIG" "$ROLE_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
  if ! grep -q "filelog/system_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding filelog/system_logs receiver"
    sudo awk '
      /^service:/ && !done {
        print ""
        print "  filelog/system_logs:"
        print "    include:"
        print "      - /var/log/syslog"
        print "      - /var/log/kern.log"
        print "      - /var/log/auth.log"
        print "    storage: file_storage/otel_pq"
        print "    retry_on_failure:"
        print "      enabled: true"
        print "      max_elapsed_time: 0"
        print "    include_file_path: true"
        print "    include_file_name: true"
        print "    operators:"
        print "      - type: copy"
        print "        from: attributes['\''log.file.name'\'']"
        print "        to: resource['\''service.name'\'']"
        print ""
        done=1
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null
    sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "filelog/vault_journalctl_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding filelog/vault_journalctl_logs receiver"
    sudo awk '
      /^service:/ && !done {
        print "  filelog/vault_journalctl_logs:"
        print "    include:"
        print "      - /var/log/vault/vault-journalctl.log"
        print "    storage: file_storage/otel_pq"
        print "    retry_on_failure:"
        print "      enabled: true"
        print "      max_elapsed_time: 0"
        print "    include_file_path: true"
        print "    include_file_name: true"
        print "    operators:"
        print "      - type: copy"
        print "        from: attributes['\''log.file.name'\'']"
        print "        to: resource['\''service.name'\'']"
        print ""
        done=1
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null
    sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "logs/system_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding logs/system_logs pipeline"
    sudo awk '
      /^[[:space:]]+pipelines:/ && !done {
        print
        print "  logs/system_logs:"
        print "    receivers: [filelog/system_logs]"
        print "    processors: [memory_limiter,resourcedetection,resource,batch]"
        print "    exporters: [otlphttp/kfuse,otlphttp/siem]"
        done=1
        next
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null
    sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "logs/vault_journalctl_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding logs/vault_journalctl_logs pipeline"
    sudo awk '
      /^[[:space:]]+pipelines:/ && !done {
        print
        print "  logs/vault_journalctl_logs:"
        print "    receivers: [filelog/vault_journalctl_logs]"
        print "    processors: [memory_limiter,resourcedetection,resource,batch]"
        print "    exporters: [otlphttp/kfuse,otlphttp/siem]"
        done=1
        next
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null
    sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"
  fi
}

function restart_zotelagent {
  log "INFO" "Fixing Vault audit/server log permissions and restarting services"

  sudo usermod -aG "$VAULT_GROUP" zotel || true
  sudo usermod -aG "$VAULT_GROUP" syslog || true

  sudo install -d -m 750 -o "$VAULT_USER" -g "$VAULT_GROUP" /var/log/vault || true

  # Audit log: Vault writes this
  if [ ! -f /var/log/vault/vault-audit.log ]; then
    sudo install -m 640 -o "$VAULT_USER" -g "$VAULT_GROUP" /dev/null /var/log/vault/vault-audit.log || true
  else
    sudo chown "$VAULT_USER:$VAULT_GROUP" /var/log/vault/vault-audit.log || true
    sudo chmod 640 /var/log/vault/vault-audit.log || true
  fi

  sudo systemctl restart zotelagent || true
  sudo systemctl restart rsyslog || true
}

function install_vault_watchdog_node {
  log "INFO" "Installing vault-watchdog-node from $WATCHDOG_BINARY_S3_URI"

  # Dedicated system user and group (idempotent)
  if ! getent group "$WATCHDOG_GROUP" >/dev/null 2>&1; then
    sudo groupadd --system "$WATCHDOG_GROUP"
  fi
  if ! getent passwd "$WATCHDOG_USER" >/dev/null 2>&1; then
    sudo useradd --system --no-create-home --shell /sbin/nologin -g "$WATCHDOG_GROUP" "$WATCHDOG_USER"
  fi

  # Directories
  sudo mkdir -p "$WATCHDOG_CONFIG_DIR" "$WATCHDOG_EVIDENCE_DIR" "$WATCHDOG_LOG_DIR"

  # Config dir is root-owned with world-readable config files.
  sudo chown root:root "$WATCHDOG_CONFIG_DIR"
  sudo chmod 755 "$WATCHDOG_CONFIG_DIR"

  # Evidence dir is owned by the watchdog user but group-owned by the Vault
  # group so the otel agent (zotel, a member of the Vault group) can read the
  # evidence files. The setgid bit makes new evidence files inherit the group.
  sudo chown "$WATCHDOG_USER:$VAULT_GROUP" "$WATCHDOG_DATA_DIR" "$WATCHDOG_EVIDENCE_DIR"
  sudo chmod 750 "$WATCHDOG_DATA_DIR"
  sudo chmod 2750 "$WATCHDOG_EVIDENCE_DIR"

  sudo chown "$WATCHDOG_USER:$WATCHDOG_GROUP" "$WATCHDOG_LOG_DIR"
  sudo chmod 750 "$WATCHDOG_LOG_DIR"

  # Download and install the binary from S3.
  aws s3 cp "$WATCHDOG_BINARY_S3_URI" "/tmp/$WATCHDOG_BINARY_NAME"
  sudo install -m 0755 -o root -g root "/tmp/$WATCHDOG_BINARY_NAME" "$WATCHDOG_INSTALL_DIR/$WATCHDOG_BINARY_NAME"
  rm -f "/tmp/$WATCHDOG_BINARY_NAME"
}

function generate_watchdog_config {
  # checks.yaml is published to S3 alongside the binary. Use the explicit URI
  # when provided, otherwise derive it from the binary URI's directory.
  local checks_uri="$WATCHDOG_CHECKS_CONFIG_S3_URI"
  if [[ -z "$checks_uri" ]]; then
    checks_uri="$(dirname "$WATCHDOG_BINARY_S3_URI")/checks.yaml"
  fi

  log "INFO" "Downloading vault-watchdog-node checks config from $checks_uri"
  aws s3 cp "$checks_uri" "/tmp/checks.yaml"
  sudo install -m 0644 -o root -g root "/tmp/checks.yaml" "$WATCHDOG_CONFIG_DIR/checks.yaml"
  rm -f "/tmp/checks.yaml"
}

function write_watchdog_token {
  # Disable xtrace for the whole function so the token is never echoed to the
  # cloud-init log (the -z test and the write both reference the token value).
  { set +x; } 2>/dev/null

  if [[ -z "$WATCHDOG_VAULT_TOKEN" ]]; then
    set -x
    log "INFO" "No Vault token supplied for watchdog; token-gated checks (e.g. VLT-007) will be skipped"
    return 0
  fi

  printf '%s' "$WATCHDOG_VAULT_TOKEN" | sudo tee "$WATCHDOG_VAULT_TOKEN_FILE" >/dev/null
  sudo chown "$WATCHDOG_USER:$WATCHDOG_GROUP" "$WATCHDOG_VAULT_TOKEN_FILE"
  sudo chmod 400 "$WATCHDOG_VAULT_TOKEN_FILE"

  set -x
  log "INFO" "Wrote Vault token for watchdog to $WATCHDOG_VAULT_TOKEN_FILE"
}

function generate_watchdog_systemd_units {
  log "INFO" "Generating vault-watchdog-node wrapper, service and timer"

  # Wrapper script builds the args and only enables the Vault token file when
  # it is present and non-empty. When no token is available the token-gated
  # checks (e.g. VLT-007) are skipped by the binary.
  sudo bash -c "cat > $WATCHDOG_INSTALL_DIR/run-vault-watchdog-node.sh" <<EOF
#!/bin/bash
set -euo pipefail

TOKEN_ARG=""
if [[ -s "$WATCHDOG_VAULT_TOKEN_FILE" ]]; then
  TOKEN_ARG="-vault-token-file $WATCHDOG_VAULT_TOKEN_FILE"
fi

exec "$WATCHDOG_INSTALL_DIR/$WATCHDOG_BINARY_NAME" -once -checks-config "$WATCHDOG_CONFIG_DIR/checks.yaml" -output-dir "$WATCHDOG_EVIDENCE_DIR" -process-name "vault" -vault-addr "$WATCHDOG_VAULT_ADDR" -vault-cluster-addr "$WATCHDOG_VAULT_CLUSTER_ADDR" -log-level "info" \$TOKEN_ARG
EOF
  sudo chmod 0755 "$WATCHDOG_INSTALL_DIR/run-vault-watchdog-node.sh"

  sudo bash -c "cat > $SYSTEMD_DIR/vault-watchdog-node.service" <<EOF
[Unit]
Description=Vault Watchdog Node (one-shot hardening evaluation)
Wants=network-online.target
After=network-online.target vault.service

[Service]
Type=oneshot
User=$WATCHDOG_USER
Group=$WATCHDOG_GROUP
UMask=0027
ExecStart=$WATCHDOG_INSTALL_DIR/run-vault-watchdog-node.sh
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$WATCHDOG_DATA_DIR $WATCHDOG_LOG_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitCORE=0
StandardOutput=journal
StandardError=journal
EOF
  sudo chmod 644 "$SYSTEMD_DIR/vault-watchdog-node.service"

  sudo bash -c "cat > $SYSTEMD_DIR/vault-watchdog-node.timer" <<EOF
[Unit]
Description=Run vault-watchdog-node every $WATCHDOG_RUN_INTERVAL

[Timer]
OnBootSec=10min
OnUnitActiveSec=$WATCHDOG_RUN_INTERVAL
Persistent=true

[Install]
WantedBy=timers.target
EOF
  sudo chmod 644 "$SYSTEMD_DIR/vault-watchdog-node.timer"
}

function start_enable_watchdog {
  sudo systemctl daemon-reload
  sudo systemctl enable vault-watchdog-node.timer
  sudo systemctl start vault-watchdog-node.timer
  # Kick off an initial evaluation immediately (best-effort).
  sudo systemctl start vault-watchdog-node.service || true
}

function generate_vault_systemd_unit_file {
  local kill_cmd=$(which kill)
  sudo bash -c "cat > $SYSTEMD_DIR/vault.service" <<EOF
[Unit]
Description="HashiCorp Vault - A tool for managing secrets"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=$VAULT_DIR_CONFIG/server.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
User=$VAULT_USER
Group=$VAULT_GROUP
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=$VAULT_DIR_BIN/vault server -config=$VAULT_DIR_CONFIG/server.hcl
ExecReload=$${kill_cmd} --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF

  sudo chmod 644 $SYSTEMD_DIR/vault.service

  mkdir /etc/systemd/system/vault.service.d
  bash -c "cat > /etc/systemd/system/vault.service.d/override.conf" <<EOF
[Service]
Environment="VAULT_ENABLE_FILE_PERMISSIONS_CHECK=true"
EOF
  chmod 0600 /etc/systemd/system/vault.service.d/override.conf
}

function generate_vault_logrotate {
  log "INFO" "Generating Vault logrotate configuration"

  sudo bash -c "cat > /etc/logrotate.d/vault" <<EOF
  /var/log/vault/vault-audit.log {
      daily
      size 100M
      rotate 90
      dateext
      dateformat .%Y%m%d_%H%M%S
      missingok
      notifempty
      nocreate
      compress
      delaycompress
      sharedscripts
      postrotate
          systemctl reload vault > /dev/null 2>&1 || true
      endscript
  }

  /var/log/vault/vault-journalctl.log {
      daily
      size 100M
      rotate 30
      dateext
      dateformat .%Y%m%d_%H%M%S
      missingok
      notifempty
      nocreate
      compress
      delaycompress
      sharedscripts
      postrotate
          systemctl reload vault > /dev/null 2>&1 || true
      endscript
  }
EOF
}

function configure_syslog_logrotate {
  log "INFO" "Configuring rsyslog logrotate retention"

  if [ -f /etc/logrotate.d/rsyslog ]; then
    sudo cp /etc/logrotate.d/rsyslog \
      /etc/logrotate.d/rsyslog.bak.$(date +%Y%m%d%H%M%S)

    sudo sed -i \
      -e 's/^\([[:space:]]*\)weekly$/\1daily/' \
      -e 's/^\([[:space:]]*\)rotate[[:space:]][0-9]\+/\1rotate 14/' \
      /etc/logrotate.d/rsyslog

    log "INFO" "Updated rsyslog logrotate configuration."
  else
    log "WARN" "/etc/logrotate.d/rsyslog not found. Skipping."
  fi
}

function start_enable_vault {
  sudo systemctl daemon-reload
  sudo systemctl enable vault
  sudo systemctl start vault
}

function configure_vault_cli {
  sudo bash -c "cat > /etc/profile.d/99-vault-cli-config.sh" <<EOF
export VAULT_ADDR=https://127.0.0.1:8200
%{ if vault_fqdn != "" ~}
export VAULT_TLS_SERVER_NAME="${vault_fqdn}"
%{ endif ~}
complete -C $VAULT_DIR_BIN/vault vault
EOF
}

exit_script() {
  if [[ "$1" == 0 ]]; then
    log "INFO" "Vault custom_data script finished successfully!"
  else
    log "ERROR" "Vault custom_data script finished with error code $1."
  fi

  exit "$1"
}

function prepare_disk() {
  local device_name="$1"
  log "DEBUG" "prepare_disk - device_name; $${device_name}"

  local device_mountpoint="$2"
  log "DEBUG" "prepare_disk - device_mountpoint; $${device_mountpoint}"

  local device_label="$3"
  log "DEBUG" "prepare_disk - device_label; $${device_label}"

  local ebs_volume_id=$(aws ec2 describe-volumes --filters Name=attachment.device,Values=$${device_name} Name=attachment.instance-id,Values=$INSTANCE_ID --query 'Volumes[*].{ID:VolumeId}' --region $REGION --output text | tr -d '-' )
  log "DEBUG" "prepare_disk - ebs_volume_id; $${ebs_volume_id}"

  local device_id=$(readlink -f /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$${ebs_volume_id})
  log "DEBUG" "prepare_disk - device_id; $${device_id}"

  mkdir $device_mountpoint

  # exclude quotes on device_label or formatting will fail
  mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0 -L $device_label $${device_id}

  echo "LABEL=$device_label $device_mountpoint ext4 defaults 0 2" >> /etc/fstab

  mount -a
}

main() {
  log "INFO" "Beginning custom_data script adding zotel meta."
  OS_DISTRO=$(detect_os_distro)
  log "INFO" "Detected OS distro is '$OS_DISTRO'."

  log "INFO" "Scraping VM metadata required for Vault configuration"
  scrape_vm_info

  log "INFO" "Installing $REQUIRED_PACKAGES $ADDITIONAL_PACKAGES"
  install_packages "$OS_DISTRO"

  log "INFO" "Disable swap at runtime"
  swapoff -a || true

  log "INFO" "Disable swap persistently in /etc/fstab"
  sed -i.bak '/\bswap\b/d' /etc/fstab || true

  log "INFO" "Installing AWS CLI"
  install_aws_cli "$OS_DISTRO"

  log "INFO" "Preparing Vault data disk"
  prepare_disk "/dev/sdf" "/opt/vault" "vault-data"

  log "INFO" "Preparing Vault audit logs disk"
  prepare_disk "/dev/sdg" "/var/log/vault" "vault-audit"

  log "INFO" "Creating Vault system user and group"
  user_group_create

  log "INFO" "Creating directories for Vault config and data"
  directory_create

  log "INFO" "Installing Vault"
  install_vault_binary

  log "INFO" "Installing Vault plugins"
  install_vault_plugins

  log "INFO" "Retrieving Vault license file from Secret Manager"
  fetch_vault_license

  log "INFO" "Retrieving Vault API TLS certificates from Secret Manager"
  fetch_tls_certificates

  log "INFO" "Generating Vault server configuration file"
  generate_vault_config

  log "INFO" "Generating Vault systemd unit file and overrides.conf"
  generate_vault_systemd_unit_file

  log "INFO" "Generating audit log and vault server log rotation script"
  generate_vault_logrotate

  log "INFO" "Generating sys log rotation script"
  configure_syslog_logrotate

  log "INFO" "Starting Vault"
  start_enable_vault

  log "INFO" "Configuring Vault CLI"
  configure_vault_cli

  log "INFO" "Installing zotelagent"
  install_zotelagent

  log "INFO" "Configuring zotelagent Vault metrics"
  configure_zotel_vault_metrics

  log "INFO" "Configuring Vault Server Logs"
  configure_vault_server_logging

  log "INFO" "Configuring patch role config"
  patch_zotel_role_config

  log "INFO" "Restarting zotelagent"
  restart_zotelagent

  if [[ -n "$WATCHDOG_BINARY_S3_URI" ]]; then
    log "INFO" "Installing vault-watchdog-node"
    { install_vault_watchdog_node \
        && generate_watchdog_config \
        && write_watchdog_token \
        && generate_watchdog_systemd_units \
        && start_enable_watchdog ; } \
      || log "ERROR" "vault-watchdog-node setup failed; continuing without it"
  else
    log "INFO" "watchdog_binary_s3_uri is empty; skipping vault-watchdog-node install"
  fi

  exit_script 0
}

main "$@"
