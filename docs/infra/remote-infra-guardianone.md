Wildon Production: 3-Tier Access Architecture with WireGuard
Context
All admin services (Grafana, Prometheus, AlertManager, ArgoCD) are currently exposed to the public internet. Prometheus and AlertManager have trivially weak basic auth (password: test). Grafana has a default password (changeme-grafana-admin). The K3s API (port 6443) is bound to all interfaces with no firewall. There is no VPN, no firewall (UFW disabled), and no network segmentation.

Goal: Implement a 3-tier access model:

Public: Only future api.wildon.zyrobyte.dev / app.wildon.zyrobyte.dev
VPN Only: Grafana (grafana.wildon.internal), ArgoCD (argocd.wildon.internal)
Cluster Internal: Prometheus, AlertManager, Redis, NATS, YugabyteDB (ClusterIP only, no ingress)
Current State (Key Facts)
Server: prod-core-01, IP 148.113.225.41, Ubuntu 24.04, K3s v1.34.3
Ingress: NGINX DaemonSet with hostNetwork: true (binds 0.0.0.0:80,443)
TLS: Cloudflare origin wildcard cert (*.wildon.zyrobyte.dev), traffic proxied via Cloudflare
WireGuard: Kernel module loaded; userspace tools NOT installed; no config
Firewall: UFW inactive, iptables ACCEPT-all
K3s API: Listening on *:6443 (publicly reachable!)
Grafana datasource: Already uses http://kube-prometheus-stack-prometheus:9090 (internal ClusterIP)
Redis/NATS/YugabyteDB: Already ClusterIP-only (no ingress) -- no changes needed for network exposure
K3s flags: --disable traefik, --write-kubeconfig-mode 644
K3s service file: /etc/systemd/system/k3s.service
Execution Plan
Phase 0: Emergency Credential Rotation (Do Immediately)
Why: We are currently exposed. Rotate before any infrastructure changes.

Back up current Helm values:


helm get values kube-prometheus-stack -n monitoring -o yaml > /root/backup-prometheus-values.yaml
helm get values argocd -n gitops -o yaml > /root/backup-argocd-values.yaml
Change Grafana admin password (generate a strong random password):


NEW_GRAFANA_PASS=$(openssl rand -base64 24)
echo "Grafana password: $NEW_GRAFANA_PASS" | sudo tee /root/grafana-password.txt
sudo chmod 600 /root/grafana-password.txt
Rotate Prometheus/AlertManager basic auth secrets (proper htpasswd file format):


NEW_BASIC_PASS=$(openssl rand -base64 16)
# NGINX expects htpasswd file format via --from-file, not --from-literal
printf "admin:$(openssl passwd -apr1 "$NEW_BASIC_PASS")\n" | \
  kubectl create secret generic prometheus-basic-auth \
    -n monitoring \
    --from-file=auth=/dev/stdin \
    --dry-run=client -o yaml | kubectl apply -f -
printf "admin:$(openssl passwd -apr1 "$NEW_BASIC_PASS")\n" | \
  kubectl create secret generic alertmanager-basic-auth \
    -n monitoring \
    --from-file=auth=/dev/stdin \
    --dry-run=client -o yaml | kubectl apply -f -
echo "Basic auth password: $NEW_BASIC_PASS" | sudo tee -a /root/grafana-password.txt
Get current ArgoCD admin password and note it:


kubectl -n gitops get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
(ArgoCD password rotation is done via the ArgoCD CLI or UI -- plan to disable admin account and use SSO later)

Save all generated credentials securely to /root/grafana-password.txt (chmod 600).

Phase 1: Remove Prometheus/AlertManager Public Ingress
Why: These are the highest risk. Even with rotated passwords, they should not be public.

Disable Prometheus and AlertManager ingresses + set new Grafana password:


helm upgrade kube-prometheus-stack kube-prometheus-stack \
  --repo https://prometheus-community.github.io/helm-charts \
  --namespace monitoring \
  --reuse-values \
  --set prometheus.ingress.enabled=false \
  --set alertmanager.ingress.enabled=false \
  --set grafana.adminPassword="$NEW_GRAFANA_PASS"
Verify:

kubectl get ingress -n monitoring -- only Grafana remains
Grafana still loads at https://grafana.wildon.zyrobyte.dev
https://prometheus.wildon.zyrobyte.dev returns 404
Prometheus still works internally (Grafana dashboards load data)
Grafana stays public temporarily until WireGuard is working (Phase 5).

Phase 2: Install and Configure WireGuard
Subnet: 10.10.0.0/24 (avoids conflict with Flannel 10.42.0.0/16 and K3s services 10.43.0.0/16)

Install wireguard-tools:


sudo apt update && sudo apt install -y wireguard-tools
Generate server keypair (correct pipeline):


sudo bash -c 'wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key'
sudo chmod 600 /etc/wireguard/server_private.key
Generate first client keypair:


wg genkey | tee /tmp/client1_private.key | wg pubkey > /tmp/client1_public.key
chmod 600 /tmp/client1_private.key
Create /etc/wireguard/wg0.conf:


[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <CONTENTS_OF_/etc/wireguard/server_private.key>

[Peer]
# Admin Client 1
PublicKey = <CONTENTS_OF_/tmp/client1_public.key>
AllowedIPs = 10.10.0.2/32
Enable and start:


sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
Verify: sudo wg show wg0, ip addr show wg0

No PostUp/PostDown NAT rules needed -- clients only access services on this server, not internet routing.

Phase 3: dnsmasq for VPN DNS (.wildon.internal)
VPN clients need *.wildon.internal to resolve to 10.10.0.1.

Install: sudo apt install -y dnsmasq

Create /etc/dnsmasq.d/wireguard.conf:


listen-address=10.10.0.1
bind-interfaces
address=/wildon.internal/10.10.0.1
# Multiple upstream DNS for resilience (don't depend on single provider)
server=1.1.1.1
server=8.8.8.8
server=213.186.33.99
no-resolv
no-hosts
This binds ONLY to 10.10.0.1:53 -- no conflict with systemd-resolved on 127.0.0.53:53.
Using no-resolv with explicit server= entries avoids reading /etc/resolv.conf (which points to systemd-resolved stub). Multiple upstream servers provide DNS resilience.

Add systemd ordering (dnsmasq must start after wg0):


sudo mkdir -p /etc/systemd/system/dnsmasq.service.d/
Create /etc/systemd/system/dnsmasq.service.d/after-wireguard.conf:


[Unit]
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
Start: sudo systemctl daemon-reload && sudo systemctl enable dnsmasq && sudo systemctl restart dnsmasq

Verify: ss -ulnp | grep ':53' -- dnsmasq on 10.10.0.1, systemd-resolved on 127.0.0.53

Phase 4: VPN Client Connection + Checkpoint
CHECKPOINT: Before moving services behind VPN, verify the VPN works end-to-end.

Generate client config and give to VPN client (see Client Config section below)
Connect as VPN client
Verify from client:
ping 10.10.0.1 -- works
dig grafana.wildon.internal @10.10.0.1 -- returns 10.10.0.1
curl --resolve grafana.wildon.internal:80:10.10.0.1 http://grafana.wildon.internal -- returns Grafana HTML
Emergency fallback (if DNS fails): VPN clients can always:

Access Grafana directly: http://10.10.0.1:80 with Host header, or add to /etc/hosts:

10.10.0.1 grafana.wildon.internal argocd.wildon.internal
DO NOT proceed to Phase 5 unless all checks pass.

Phase 5: Move Grafana + ArgoCD Behind VPN
Defense in depth: The whitelist annotation (10.10.0.0/24) is an extra security layer, not the sole gate. The primary protection is:

Cloudflare DNS records removed (Phase 6) -- no public resolution
VPN-only DNS via dnsmasq -- .internal only resolves on VPN
Whitelist annotation -- even if someone spoofs Host header to public IP, gets 403
Since NGINX uses hostNetwork: true, it sees real kernel source IPs (no proxy headers to spoof). VPN clients arrive from 10.10.0.x. Public traffic arrives from real public IPs. The whitelist is trustworthy here.

HTTP over VPN: No TLS on .internal ingresses. WireGuard encrypts the tunnel. Acceptable for now. (Future: consider internal TLS for Grafana/ArgoCD session cookies if desired.)

Switch Grafana to VPN-only:


helm upgrade kube-prometheus-stack kube-prometheus-stack \
  --repo https://prometheus-community.github.io/helm-charts \
  --namespace monitoring \
  --reuse-values \
  --set prometheus.ingress.enabled=false \
  --set alertmanager.ingress.enabled=false \
  --set grafana.ingress.enabled=true \
  --set grafana.ingress.ingressClassName=nginx \
  --set grafana.ingress.hosts[0]=grafana.wildon.internal \
  --set 'grafana.ingress.annotations.nginx\.ingress\.kubernetes\.io/whitelist-source-range=10.10.0.0/24' \
  --set 'grafana.ingress.annotations.nginx\.ingress\.kubernetes\.io/backend-protocol=HTTP' \
  --set grafana.ingress.path=/ \
  --set grafana.ingress.tls=null
Switch ArgoCD to VPN-only (also fixes the broken argocd-server-tls secret reference):


helm upgrade argocd argo-cd \
  --repo https://argoproj.github.io/argo-helm \
  --namespace gitops \
  --reuse-values \
  --set server.ingress.enabled=true \
  --set server.ingress.ingressClassName=nginx \
  --set server.ingress.hosts[0]=argocd.wildon.internal \
  --set 'server.ingress.annotations.nginx\.ingress\.kubernetes\.io/whitelist-source-range=10.10.0.0/24' \
  --set 'server.ingress.annotations.nginx\.ingress\.kubernetes\.io/backend-protocol=HTTP' \
  --set 'server.ingress.annotations.nginx\.ingress\.kubernetes\.io/force-ssl-redirect=false' \
  --set server.ingress.tls=null \
  --set global.domain=argocd.wildon.internal
Verify from VPN client:

curl http://grafana.wildon.internal -- 200 OK
curl http://argocd.wildon.internal -- 200 OK
Verify from public:

curl -H "Host: grafana.wildon.internal" http://148.113.225.41 -- 403 Forbidden
Phase 6: Remove Cloudflare DNS Records
In Cloudflare dashboard, delete A/CNAME records for:

prometheus.wildon.zyrobyte.dev
alertmanager.wildon.zyrobyte.dev
grafana.wildon.zyrobyte.dev
argocd.wildon.zyrobyte.dev
Keep the wildcard *.wildon.zyrobyte.dev for future public services (api., app.).

Phase 7: Enable UFW Firewall
Critical: Use a safety timer to auto-disable UFW if SSH breaks.

Edit /etc/default/ufw -- change DEFAULT_FORWARD_POLICY from "DROP" to "ACCEPT" (required for K3s pod networking)

Add K3s forwarding rules to /etc/ufw/before.rules (before COMMIT in the *filter section):


# K3s pod and service networking
-A ufw-before-forward -s 10.42.0.0/16 -j ACCEPT
-A ufw-before-forward -d 10.42.0.0/16 -j ACCEPT
-A ufw-before-forward -s 10.43.0.0/16 -j ACCEPT
-A ufw-before-forward -d 10.43.0.0/16 -j ACCEPT
Set safety timer: echo "sudo ufw disable" | sudo at now + 5 minutes

Apply UFW rules:


# Allow SSH (must be first)
sudo ufw allow 22/tcp comment 'SSH'

# Public web (NGINX ingress)
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# WireGuard
sudo ufw allow 51820/udp comment 'WireGuard'

# K3s API - VPN only
sudo ufw allow from 10.10.0.0/24 to any port 6443 proto tcp comment 'K3s API via VPN'

# DNS for VPN clients - interface-specific (not open on public)
sudo ufw allow in on wg0 to any port 53 proto udp comment 'VPN DNS UDP'
sudo ufw allow in on wg0 to any port 53 proto tcp comment 'VPN DNS TCP'

# Allow all traffic on wg0 interface
sudo ufw allow in on wg0 comment 'WireGuard interface'

# Explicitly block dangerous ports (defense in depth even with default deny)
sudo ufw deny 10250/tcp comment 'kubelet block'
sudo ufw deny 10256/tcp comment 'kube-proxy health block'
sudo ufw deny 9100/tcp comment 'node-exporter block'
sudo ufw deny 30000:32767/tcp comment 'NodePort range block'
sudo ufw deny 30000:32767/udp comment 'NodePort range block'

# Enable
sudo ufw --force enable
Immediately test SSH from another terminal. If OK, cancel safety timer:


sudo atrm $(atq | awk '{print $1}')
Verify UFW rule ordering (denies must come after allows):


sudo ufw status numbered
Verify K3s pods still work: kubectl get pods -A

Verify K3s API is firewalled:


# Confirm 6443 is on 0.0.0.0 (expected -- UFW blocks public access)
ss -tlnp | grep 6443
# From an external machine, verify 6443 is unreachable
OVH network firewall: As an additional layer, configure OVH's network-level firewall (if available on your plan) to block port 6443 from 0.0.0.0/0. Defense in depth -- protects K3s API even if UFW is ever disabled.

Phase 7.5: Restrict SSH to VPN Only (After VPN Stable)
Only do this after you've confirmed VPN access is reliable for several days.


sudo ufw delete allow 22/tcp
sudo ufw allow from 10.10.0.0/24 to any port 22 proto tcp comment 'SSH via VPN only'
Fallback: OVH KVM/IPMI console access if locked out. Ensure you have console access before this step.

Phase 8: K3s API via VPN (kubectl access)
Add --tls-san entries to K3s service file (/etc/systemd/system/k3s.service ExecStart line).
Keep both the public IP and VPN IP to avoid breaking existing cert validation:


ExecStart=/usr/local/bin/k3s \
    server \
    '--write-kubeconfig-mode' \
    '644' \
    '--disable' \
    'traefik' \
    '--tls-san' \
    '10.10.0.1' \
    '--tls-san' \
    '148.113.225.41' \
Restart K3s (brief API downtime):


sudo systemctl daemon-reload && sudo systemctl restart k3s
Export VPN kubeconfig:


sudo cat /etc/rancher/k3s/k3s.yaml | sed 's|127.0.0.1|10.10.0.1|g' > /tmp/vpn-kubeconfig.yaml
Transfer to client and test: kubectl --kubeconfig=vpn-kubeconfig.yaml get nodes

Phase 9 (Follow-up): Harden Internal Services
Redis: helm upgrade redis redis --repo https://charts.bitnami.com/bitnami -n database --reuse-values --set auth.password="<STRONG_PASSWORD>" (update app configs)
NATS: Enable auth via Helm values
YugabyteDB: Enable YSQL password auth
Clean up stuck Grafana CrashLoopBackOff pod if still present
Client WireGuard Config Template

[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.10.0.2/32
DNS = 10.10.0.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = 148.113.225.41:51820
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
Split tunnel: only 10.10.0.0/24 routes through VPN. Normal internet unaffected. DNS setting ensures .wildon.internal resolves via dnsmasq on the server.

Emergency access (if DNS fails):

Add to client /etc/hosts: 10.10.0.1 grafana.wildon.internal argocd.wildon.internal
Or access directly: http://10.10.0.1 with appropriate Host header
Rollback
Each phase is independently reversible:

Phase 0: Passwords are one-way; old passwords no longer work (this is intentional)
Phase 1: helm upgrade kube-prometheus-stack ... -n monitoring -f /root/backup-prometheus-values.yaml
Phase 2: sudo systemctl stop wg-quick@wg0 && sudo systemctl disable wg-quick@wg0
Phase 3: sudo systemctl stop dnsmasq && sudo systemctl disable dnsmasq
Phase 5: helm upgrade ... -f /root/backup-prometheus-values.yaml + -f /root/backup-argocd-values.yaml
Phase 7: sudo ufw disable
Phase 7.5: sudo ufw delete allow from 10.10.0.0/24 to any port 22 then sudo ufw allow 22/tcp
Critical Files Modified
File	Action	Purpose
/etc/wireguard/wg0.conf	Create	WireGuard server config
/etc/wireguard/server_private.key	Create	Server private key (chmod 600)
/etc/wireguard/server_public.key	Create	Server public key
/etc/dnsmasq.d/wireguard.conf	Create	VPN DNS for .wildon.internal
/etc/systemd/system/dnsmasq.service.d/after-wireguard.conf	Create	dnsmasq start ordering
/etc/default/ufw	Edit	Set DEFAULT_FORWARD_POLICY="ACCEPT"
/etc/ufw/before.rules	Edit	Add K3s CIDR forward rules
/etc/systemd/system/k3s.service	Edit	Add --tls-san 10.10.0.1
/root/grafana-password.txt	Create	Credential store (chmod 600)
Verification Summary
After full completion, from a VPN client:

http://grafana.wildon.internal -- works (200)
http://argocd.wildon.internal -- works (200)
kubectl --kubeconfig=vpn-kubeconfig.yaml get nodes -- works
ping 10.10.0.1 -- works
dig grafana.wildon.internal @10.10.0.1 -- returns 10.10.0.1
From public internet:

https://prometheus.wildon.zyrobyte.dev -- dead (no DNS, no ingress)
https://alertmanager.wildon.zyrobyte.dev -- dead (no DNS, no ingress)
https://grafana.wildon.zyrobyte.dev -- dead (no DNS, no ingress)
https://argocd.wildon.zyrobyte.dev -- dead (no DNS, no ingress)
curl -H "Host: grafana.wildon.internal" http://148.113.225.41 -- 403 Forbidden
Port 6443 -- blocked by UFW
Port 10250/9100/30000-32767 -- explicitly blocked by UFW
Port 9090/9093/6379/4222/5433 -- blocked by default deny