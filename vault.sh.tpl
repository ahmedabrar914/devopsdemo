# --- ZOTEL / OTel Agent settings ---
ZOTEL_INSTALL_DIR="${zotel_install_dir}"
ZOTEL_INSTALLER_S3_URI="${zotel_installer_s3_uri}"
ZOTEL_INSTALLER_NAME="${zotel_installer_name}"
ZOTEL_SERVICE_GROUP="${zotel_service_group}"
ZOTEL_INGEST_HOST="${zotel_ingest_host}"
ZOTEL_INGEST_TOKEN="${zotel_ingest_token}"

function install_zotelagent {
  log "INFO" "Installing zotelagent into ${ZOTEL_INSTALL_DIR}"

  sudo mkdir -p "${ZOTEL_INSTALL_DIR}"
  cd "${ZOTEL_INSTALL_DIR}"

  log "INFO" "Downloading installer: ${ZOTEL_INSTALLER_S3_URI}"
  aws s3 cp "${ZOTEL_INSTALLER_S3_URI}" "./${ZOTEL_INSTALLER_NAME}"
  sudo chmod +x "./${ZOTEL_INSTALLER_NAME}"

  log "INFO" "Running installer"
  sudo env ZOTELAGENT_INSTALL_PATH="${ZOTEL_INSTALL_DIR}" ZOTEL_SERVICE_GROUP="${ZOTEL_SERVICE_GROUP}" \
    "./${ZOTEL_INSTALLER_NAME}" install -d "${ZOTEL_INGEST_HOST}" -t "${ZOTEL_INGEST_TOKEN}"

  log "INFO" "Running linux_parsing.sh"
  sudo "${ZOTEL_INSTALL_DIR}/zotelagent/utils/linux_parsing.sh"

  log "INFO" "Setting service_group in resource-config.yaml"
  sudo sed -i '/key: service_group/{n;s/value: .*/value: '"${ZOTEL_SERVICE_GROUP}"'/}' \
    "${ZOTEL_INSTALL_DIR}/zotelagent/conf/resource-config.yaml"
}

function configure_zotel_vault_metrics {
  log "INFO" "Configuring zotel prometheus scrape config for Vault"

  sudo tee "${ZOTEL_INSTALL_DIR}/zotelagent/conf/prometheus_simple_config.yaml" >/dev/null <<EOF
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
    metrics:
      receivers: [prometheus]
      processors: [memory_limiter,resourcedetection,resource,batch]
      exporters: [otlphttp/kfuse]
EOF
}

function restart_zotelagent {
  log "INFO" "Adding zotel user to vault group and restarting zotelagent"

  sudo usermod -aG $VAULT_GROUP zotel || true

  # Your script already mounts /var/log/vault on /dev/sdg; ensure permissions are safe
  sudo chmod 750 /var/log/vault || true
  sudo chown -R $VAULT_USER:$VAULT_GROUP /var/log/vault || true

  sudo systemctl restart zotelagent || true
}

  log "INFO" "Installing zotelagent"
  install_zotelagent

  log "INFO" "Configuring zotelagent Vault metrics"
  configure_zotel_vault_metrics

  log "INFO" "Restarting zotelagent"
  restart_zotelagent