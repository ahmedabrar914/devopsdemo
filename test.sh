Yes. Implement it like this: patch existing role-config.yaml only if entries are missing.

1. Add variables

ROLE_CONFIG="/sc/zotelagent/conf/role-config.yaml"

2. Add Vault server rsyslog function

function configure_vault_server_logging {
  log "INFO" "Configuring Vault server logs"
  sudo install -d -m 775 -o syslog -g adm /var/log/vault
  sudo touch /var/log/vault/vault-server.log
  sudo chown syslog:adm /var/log/vault
  sudo chmod 775 /var/log/vault
  sudo chown syslog:adm /var/log/vault/vault-server.log
  sudo chmod 664 /var/log/vault/vault-server.log
  sudo tee /etc/rsyslog.d/10-vault-journal.conf >/dev/null <<'EOF'
module(load="imjournal" StateFile="imjournal-vault.state")
if ($syslogtag startswith "vault[") then {
    action(type="omfile" file="/var/log/vault/vault-server.log")
    stop
}
EOF
  sudo rsyslogd -N1
  sudo systemctl restart rsyslog
}

3. Add role-config patch function

function patch_zotel_role_config {
  log "INFO" "Patching Zotel role-config if system/vault-server logs are missing"
  if [ ! -f "$ROLE_CONFIG" ]; then
    log "WARN" "$ROLE_CONFIG not found, skipping patch"
    return 0
  fi
  sudo cp "$ROLE_CONFIG" "${ROLE_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  if ! grep -q "filelog/system_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding filelog/system_logs receiver"
    sudo awk '
      /^service:/ && !done {
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
    ' "$ROLE_CONFIG" | sudo tee "${ROLE_CONFIG}.tmp" >/dev/null
    sudo mv "${ROLE_CONFIG}.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "filelog/vault_server_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding filelog/vault_server_logs receiver"
    sudo awk '
      /^service:/ && !done {
        print "  filelog/vault_server_logs:"
        print "    include:"
        print "      - /var/log/vault/vault-server.log"
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
    ' "$ROLE_CONFIG" | sudo tee "${ROLE_CONFIG}.tmp" >/dev/null
    sudo mv "${ROLE_CONFIG}.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "logs/system_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding logs/system_logs pipeline"
    sudo awk '
      /^[[:space:]]+pipelines:/ && !done {
        print
        print "    logs/system_logs:"
        print "      receivers: [filelog/system_logs]"
        print "      processors: [memory_limiter,resourcedetection,resource,batch]"
        print "      exporters: [otlphttp/kfuse]"
        done=1
        next
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "${ROLE_CONFIG}.tmp" >/dev/null
    sudo mv "${ROLE_CONFIG}.tmp" "$ROLE_CONFIG"
  fi
  if ! grep -q "logs/vault_server_logs:" "$ROLE_CONFIG"; then
    log "INFO" "Adding logs/vault_server_logs pipeline"
    sudo awk '
      /^[[:space:]]+pipelines:/ && !done {
        print
        print "    logs/vault_server_logs:"
        print "      receivers: [filelog/vault_server_logs]"
        print "      processors: [memory_limiter,resourcedetection,resource,batch]"
        print "      exporters: [otlphttp/kfuse]"
        done=1
        next
      }
      { print }
    ' "$ROLE_CONFIG" | sudo tee "${ROLE_CONFIG}.tmp" >/dev/null
    sudo mv "${ROLE_CONFIG}.tmp" "$ROLE_CONFIG"
  fi
}

4. Call in correct order

Call these after Zotel role-config is downloaded/generated, and after /var/log/vault is created by Vault setup:

configure_vault_server_logging
patch_zotel_role_config
restart_zotelagent

5. Validate on new instance

sudo grep -n "filelog/system_logs" /sc/zotelagent/conf/role-config.yaml
sudo grep -n "filelog/vault_server_logs" /sc/zotelagent/conf/role-config.yaml
sudo grep -n "logs/system_logs" /sc/zotelagent/conf/role-config.yaml
sudo grep -n "logs/vault_server_logs" /sc/zotelagent/conf/role-config.yaml
sudo rsyslogd -N1
sudo systemctl restart vault
sudo tail -20 /var/log/vault/vault-server.log

In KFuse search:

source="vault-server.log"

function patch_zotel_role_config {
  local ROLE_CONFIG="/sc/zotelagent/conf/role-config.yaml"

  log "INFO" "Patching Zotel role-config if system/vault-server logs are missing"

  if [ ! -f "$ROLE_CONFIG" ]; then
    log "WARN" "$ROLE_CONFIG not found, skipping patch"
    return 0
  fi

  sudo cp "$ROLE_CONFIG" "$ROLE_CONFIG.bak.$(date +%Y%m%d%H%M%S)"

  # Add missing receivers before service:
  sudo awk '
    /^service:/ && !done {
      if (!has_system) {
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
        print "        from: attributes[\"log.file.name\"]"
        print "        to: resource[\"service.name\"]"
        print ""
      }

      if (!has_vault_server) {
        print "  filelog/vault_server_logs:"
        print "    include:"
        print "      - /var/log/vault/vault-server.log"
        print "    storage: file_storage/otel_pq"
        print "    retry_on_failure:"
        print "      enabled: true"
        print "      max_elapsed_time: 0"
        print "    include_file_path: true"
        print "    include_file_name: true"
        print "    operators:"
        print "      - type: copy"
        print "        from: attributes[\"log.file.name\"]"
        print "        to: resource[\"service.name\"]"
        print ""
      }

      done=1
    }

    /filelog\/system_logs:/ { has_system=1 }
    /filelog\/vault_server_logs:/ { has_vault_server=1 }

    { print }
  ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null

  sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"

  # Add missing pipelines before logs/vault_as_a_service_1:
  sudo awk '
    BEGIN {
      add_system=1
      add_vault_server=1
    }

    /logs\/system_logs:/ {
      add_system=0
    }

    /logs\/vault_server_logs:/ {
      add_vault_server=0
    }

    /^    logs\/vault_as_a_service_1:/ && !done {
      if (add_vault_server) {
        print "    logs/vault_server_logs:"
        print "      receivers: [filelog/vault_server_logs]"
        print "      processors: [memory_limiter,resourcedetection,resource,batch]"
        print "      exporters: [otlphttp/kfuse]"
        print ""
      }

      if (add_system) {
        print "    logs/system_logs:"
        print "      receivers: [filelog/system_logs]"
        print "      processors: [memory_limiter,resourcedetection,resource,batch]"
        print "      exporters: [otlphttp/kfuse]"
        print ""
      }

      done=1
    }

    { print }
  ' "$ROLE_CONFIG" | sudo tee "$ROLE_CONFIG.tmp" >/dev/null

  sudo mv "$ROLE_CONFIG.tmp" "$ROLE_CONFIG"

  log "INFO" "Completed Zotel role-config patch"
}


Key point: do not overwrite role-config. Only patch missing receivers and pipelines.