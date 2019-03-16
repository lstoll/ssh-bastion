#!/usr/bin/env bash
set -euo pipefail

export VAULT_TOKEN=vault-root-token
export VAULT_ADDR=http://localhost:8200

keyfile=$HOME/.ssh/id_rsa.pub
if [ -n "${1:-}" ]; then
    keyfile="$1"
fi

tmpfile=$(mktemp /tmp/signed-ssh.XXXXXXXXXXXX)

vault write -field=signed_key ssh-client-signer/sign/my-role public_key=@$keyfile > $tmpfile

exec ssh -i $tmpfile -i $keyfile -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@localhost
