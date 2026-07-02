function configure_syslog_permissions_for_zotel {
  log "INFO" "Configuring syslog/auth/kern log permissions for zotel"

  # Allow zotel to read Ubuntu/Debian system logs owned by adm group
  if id zotel >/dev/null 2>&1; then
    sudo usermod -aG adm zotel || true
  else
    log "WARN" "zotel user not found, skipping adm group update"
  fi

  # Ensure current files are readable by zotel even if group permission is not enough
  for logfile in /var/log/syslog /var/log/kern.log /var/log/auth.log; do
    if [ -f "$logfile" ]; then
      sudo chmod o+r "$logfile" || true
    else
      log "WARN" "$logfile not found, skipping permission update"
    fi
  done
}