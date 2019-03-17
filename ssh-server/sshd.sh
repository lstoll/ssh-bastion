#!/bin/bash
set -euo pipefail

echo "--> Waiting for vault to start"
timeout 30 sh -c 'until nc -z $0 $1; do sleep 1; done' vault 8200

if [ "$(vault secrets list | grep -c ssh-client-signer)" -eq 0 ]; then
    echo "--> Configuring vault SSH"
    vault secrets enable -path=ssh-client-signer ssh
    vault write ssh-client-signer/config/ca generate_signing_key=true
    vault write ssh-client-signer/roles/my-role -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "default_user": "vault",
  "ttl": "30m0s"
}
EOH
fi

vault read -field=public_key ssh-client-signer/config/ca > /etc/ssh/trusted-user-ca-keys.pem

echo "--> Launching SSHD"
/usr/sbin/sshd -d