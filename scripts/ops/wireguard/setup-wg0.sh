#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   WG_PRIVATE_KEY='<private_key>' scripts/ops/wireguard/setup-wg0.sh

if [ -z "${WG_PRIVATE_KEY:-}" ]; then
  echo "WG_PRIVATE_KEY is required"
  echo "example: WG_PRIVATE_KEY='<key>' scripts/ops/wireguard/setup-wg0.sh"
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required"
  exit 1
fi

sudo -v

if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y wireguard-tools
fi

sudo tee /etc/wireguard/wg0.conf >/dev/null <<EOF_CONF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = 10.10.0.2/32
DNS = 10.10.0.1

[Peer]
PublicKey = UvjNS18CNOkPTEB3kd1Y1lpYZIgdZXGZgnfgqimEwBE=
Endpoint = 148.113.225.41:51820
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF_CONF

sudo chmod 600 /etc/wireguard/wg0.conf

if sudo wg show wg0 >/dev/null 2>&1; then
  sudo wg-quick down wg0
fi

sudo wg-quick up wg0

echo "testing tunnel"
ping -c 3 10.10.0.1

echo "WireGuard is up. Next: run scripts/ops/wireguard/check-internal-endpoints.sh"
