user_data = base64encode(<<-EOF
#!/bin/bash
set -xeuo pipefail

if ! command -v aws >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y unzip curl
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
fi

aws s3 cp s3://${var.bootstrap_bucket_name}/${aws_s3_object.install_vault_script.key} /tmp/install-vault.sh
chmod 700 /tmp/install-vault.sh
/tmp/install-vault.sh
EOF
)


resource "aws_s3_object" "install_vault_script" {
  bucket = var.otel_bucket_name
  key    = "vault-bootstrap/install-vault.sh"

  content = templatefile(
    "${path.module}/templates/install-vault.sh.tpl",
    local.vault_user_data_template_vars
  )

  tags = var.resource_tags
}

user_data = base64encode(<<-EOF
#!/bin/bash
set -xeuo pipefail

aws s3 cp s3://${var.otel_bucket_name}/${aws_s3_object.install_vault_script.key} /tmp/install-vault.sh
chmod 700 /tmp/install-vault.sh
/tmp/install-vault.sh
EOF
)