#!/usr/bin/env bash
set -euo pipefail

GRAFANA_URL="${GRAFANA_URL:-${INTERNAL_GRAFANA_URL:-http://grafana.wildon.internal}}"
ARGOCD_URL="${ARGOCD_URL:-${INTERNAL_ARGOCD_URL:-http://argocd.wildon.internal}}"
K3S_API_URL="${K3S_API_URL:-https://10.10.0.1:6443}"

echo "wireguard interface status"
sudo wg show wg0 || true

echo "dns resolution"
getent hosts grafana.wildon.internal || echo "grafana DNS lookup failed"
getent hosts argocd.wildon.internal || echo "argocd DNS lookup failed"

echo "http reachability"
curl -sS -I --max-time 10 "$GRAFANA_URL" | head -n 1 || echo "cannot reach $GRAFANA_URL"
curl -sS -I --max-time 10 "$ARGOCD_URL" | head -n 1 || echo "cannot reach $ARGOCD_URL"
curl -k -sS --max-time 10 "${K3S_API_URL}/version" | head -c 200 || echo "cannot reach ${K3S_API_URL}"
echo

echo "If DNS fails but VPN is up, ask infra for internal DNS forwarding or add temporary /etc/hosts entries."
