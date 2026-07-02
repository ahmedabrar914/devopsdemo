Yes, we can do same approach: create a separate rsyslog-generated kern log file and make Zotel read that file instead of /var/log/kern.log.

Do manual test first.

1. Create custom rsyslog file for kern logs

sudo tee /etc/rsyslog.d/20-kern-zotel.conf >/dev/null <<'EOF'
kern.*    /var/log/kern-zotel.log
EOF

2. Create file with readable permission

sudo install -m 664 -o syslog -g adm /dev/null /var/log/kern-zotel.log
sudo chmod o+r /var/log/kern-zotel.log

3. Restart rsyslog

sudo systemctl restart rsyslog

4. Generate test kernel log

echo "KFUSE-KERN-ZOTEL-TEST-$(date +%s)" | sudo tee /dev/kmsg

5. Check new file

sudo tail -20 /var/log/kern-zotel.log

You should see:

KFUSE-KERN-ZOTEL-TEST

6. Update Zotel role config manually

Edit:

sudo vi /sc/zotelagent/conf/role-config.yaml

Change this:

- /var/log/kern.log

to:

- /var/log/kern-zotel.log

So it becomes:

filelog/system_logs:
  include:
    - /var/log/syslog
    - /var/log/kern-zotel.log
    - /var/log/auth.log

7. Restart Zotel

sudo systemctl restart zotelagent

8. Generate another fresh test

echo "KFUSE-KERN-ZOTEL-FINAL-$(date +%s)" | sudo tee /dev/kmsg

Then check:

sudo tail -20 /var/log/kern-zotel.log

Search in Kfuse:

KFUSE-KERN-ZOTEL-FINAL

If this works, we’ll add the same permanently in launch template:

configure_kern_log_for_zotel

and patch role config to use:

/var/log/kern-zotel.log