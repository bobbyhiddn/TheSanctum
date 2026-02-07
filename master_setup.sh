#!/usr/bin/env bash
#===============================================================================

# 

# MASTER NODE SETUP — Debian 13 Trixie

# DreamQuest Pro N95 · 16GB RAM · 512GB SSD · Dual GbE

# 

# Layers:  Incus (Zabbly stable) → K3s (stable channel) → Big Bang ready

# Desktop: Hyprland via JaKooLit (interactive — launched at end)

# Dev:     Go 1.25, Node 22 LTS, Rust, Python 3, VSCode, k9s, Helm, Flux

# 

# Usage:

# chmod +x master-node-setup.sh

# sudo ./master-node-setup.sh

# 

# Run as root on a fresh Debian 13 netinstall (SSH server + standard utils).

# Do NOT select a desktop environment during install — Hyprland replaces it.

# 

#===============================================================================

set -Eeuo pipefail
trap ‘err “Script failed at line $LINENO. Check output above.”; exit 1’ ERR

# ── Config ────────────────────────────────────────────────────────────────────

NODE_NAME=“masternode”
INCUS_BRIDGE_SUBNET=“10.10.10.1/24”
GO_VERSION=“1.25.7”
K9S_VERSION=“v0.32.7”
METALLB_VERSION=“v0.14.9”

MAIN_USER=”${SUDO_USER:-$(logname 2>/dev/null || echo ‘’)}”

# ── Colors & logging ─────────────────────────────────────────────────────────

RED=’\033[0;31m’; GREEN=’\033[0;32m’; YELLOW=’\033[1;33m’
CYAN=’\033[0;36m’; BOLD=’\033[1m’; NC=’\033[0m’

log()   { echo -e “${GREEN}  [✓]${NC} $*”; }
warn()  { echo -e “${YELLOW}  [!]${NC} $*”; }
err()   { echo -e “${RED}  [✗]${NC} $*” >&2; }
phase() {
echo “”
echo -e “${CYAN}  ═══════════════════════════════════════════════════════════${NC}”
echo -e “${CYAN}    $*${NC}”
echo -e “${CYAN}  ═══════════════════════════════════════════════════════════${NC}”
echo “”
}

# ── Preflight ─────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
err “Run as root: sudo ./master-node-setup.sh”
exit 1
fi

if [[ -z “$MAIN_USER” || “$MAIN_USER” == “root” ]]; then
err “Cannot detect non-root user. Run with sudo, not as root directly.”
exit 1
fi

MAIN_HOME=$(eval echo “~${MAIN_USER}”)

source /etc/os-release 2>/dev/null || { err “Cannot read /etc/os-release”; exit 1; }
if [[ “$VERSION_CODENAME” != “trixie” ]]; then
warn “Expected Debian 13 (trixie), got: $PRETTY_NAME”
read -rp “  Continue anyway? [y/N] “ ans
[[ “$ans” =~ ^[Yy]$ ]] || exit 0
fi

ARCH=$(dpkg –print-architecture)
PRIMARY_IP=$(hostname -I | awk ‘{print $1}’)

echo “”
echo -e “  ${BOLD}Master Node Setup${NC}”
echo -e “  OS:       $PRETTY_NAME ($ARCH)”
echo -e “  User:     $MAIN_USER”
echo -e “  IP:       $PRIMARY_IP”
echo -e “  Hostname: $NODE_NAME”
echo “”
read -rp “  Press Enter to begin (Ctrl+C to abort)… “

START_TIME=$SECONDS

#===============================================================================

# PHASE 1 — SYSTEM FOUNDATIONS

#===============================================================================
phase “Phase 1 · System Foundations”

hostnamectl set-hostname “$NODE_NAME”
log “Hostname → $NODE_NAME”

# ── Enable contrib + non-free-firmware in deb822 or legacy format ─────────

if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
# deb822 format (Trixie default)
SRCFILE=”/etc/apt/sources.list.d/debian.sources”
if ! grep -q “non-free-firmware” “$SRCFILE”; then
sed -i ‘s/^Components: main$/Components: main contrib non-free-firmware/’ “$SRCFILE”
log “Enabled contrib + non-free-firmware (deb822)”
fi
# Enable deb-src (needed for Hyprland build deps later)
if ! grep -q “deb-src” “$SRCFILE”; then
sed -i ‘s/^Types: deb$/Types: deb deb-src/’ “$SRCFILE”
log “Enabled deb-src repositories”
fi
elif [[ -f /etc/apt/sources.list ]]; then
if ! grep -q “non-free-firmware” /etc/apt/sources.list; then
sed -i ‘s/main$/main contrib non-free-firmware/’ /etc/apt/sources.list
log “Enabled contrib + non-free-firmware (legacy)”
fi
fi

# ── Full upgrade ──────────────────────────────────────────────────────────

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get full-upgrade -y -qq
log “System fully upgraded”

# ── Core packages ─────────────────────────────────────────────────────────

apt-get install -y -qq   
curl wget git gnupg2 ca-certificates lsb-release   
apt-transport-https software-properties-common   
sudo vim nano   
htop btop fastfetch   
tmux screen   
tree jq unzip zip pigz zstd   
net-tools iproute2 dnsutils iputils-ping traceroute nmap   
openssh-server ufw fail2ban   
bash-completion zsh   
build-essential gcc g++ make cmake pkg-config autoconf automake libtool   
python3 python3-pip python3-venv python3-full   
rsync lsof strace   
fuse3   
apparmor apparmor-utils   
ethtool   
firmware-linux-nonfree   
whiptail
log “Core packages installed”

#===============================================================================

# PHASE 2 — NETWORK & SECURITY

#===============================================================================
phase “Phase 2 · Network & Security”

# ── SSH hardening ─────────────────────────────────────────────────────────

sed -i ‘s/^#?PermitRootLogin.*/PermitRootLogin no/’          /etc/ssh/sshd_config
sed -i ’s/^#?PasswordAuthentication.*/PasswordAuthentication yes/’ /etc/ssh/sshd_config
systemctl enable –now ssh
log “SSH hardened (root login disabled)”

# ── UFW firewall ──────────────────────────────────────────────────────────

ufw default deny incoming
ufw default allow outgoing

# Management

ufw allow ssh                comment “SSH”
ufw allow 8443/tcp           comment “Incus API + Web UI”

# K3s cluster

ufw allow 6443/tcp           comment “K3s API server”
ufw allow 8472/udp           comment “K3s Flannel VXLAN”
ufw allow 10250/tcp          comment “Kubelet metrics”
ufw allow 51820/udp          comment “K3s Flannel WireGuard”
ufw allow 5001/tcp           comment “K3s embedded registry”
ufw allow 2379:2380/tcp      comment “etcd client+peer”

# Services

ufw allow 80/tcp             comment “HTTP”
ufw allow 443/tcp            comment “HTTPS”

# PXE (future use)

ufw allow 67/udp             comment “DHCP (PXE)”
ufw allow 69/udp             comment “TFTP (PXE)”
ufw allow 4011/udp           comment “PXE proxy DHCP”

ufw –force enable
log “Firewall configured”

# ── Fail2ban ──────────────────────────────────────────────────────────────

systemctl enable –now fail2ban
log “Fail2ban enabled”

#===============================================================================

# PHASE 3 — INCUS (Zabbly Stable)

#===============================================================================
phase “Phase 3 · Incus (Zabbly Stable Repository)”

# ── Import and verify Zabbly GPG key ─────────────────────────────────────

mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc

EXPECTED_FP=“4EFC590696CB15B87C73A3AD82CC8797C838DCFD”
ACTUAL_FP=$(gpg –show-keys –with-colons /etc/apt/keyrings/zabbly.asc 2>/dev/null   
| awk -F: ‘/^fpr:/{print $10; exit}’)

if [[ “$ACTUAL_FP” == “$EXPECTED_FP” ]]; then
log “Zabbly GPG key verified ✓”
else
warn “GPG fingerprint mismatch!”
warn “  Expected: $EXPECTED_FP”
warn “  Got:      $ACTUAL_FP”
read -rp “  Continue? [y/N] “ ans
[[ “$ans” =~ ^[Yy]$ ]] || exit 1
fi

# ── Add Zabbly Incus stable repo ─────────────────────────────────────────

cat <<EOF > /etc/apt/sources.list.d/zabbly-incus-stable.sources
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${VERSION_CODENAME}
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF

apt-get update -qq
apt-get install -y -qq incus incus-extra incus-ui-canonical
log “Incus installed (containers + VMs + web UI)”

# ── User permissions ──────────────────────────────────────────────────────

usermod -aG incus-admin “$MAIN_USER”
usermod -aG incus “$MAIN_USER”
log “User $MAIN_USER → incus-admin, incus groups”

# ── Initialize Incus with preseed ─────────────────────────────────────────

# Uses ‘dir’ storage driver for simplicity on a single-SSD system.

# Switch to ZFS or btrfs later if you partition a dedicated pool.

cat <<PRESEED | incus admin init –preseed || warn “Preseed failed — run ‘incus admin init’ manually”
config:
core.https_address: “:8443”
networks:

- name: incusbr0
  type: bridge
  config:
  ipv4.address: “${INCUS_BRIDGE_SUBNET}”
  ipv4.nat: “true”
  ipv6.address: auto
  storage_pools:
- name: default
  driver: dir
  profiles:
- name: default
  devices:
  root:
  path: /
  pool: default
  type: disk
  eth0:
  name: eth0
  network: incusbr0
  type: nic
  cluster: null
  PRESEED

log “Incus initialized — bridge ${INCUS_BRIDGE_SUBNET}, web UI on :8443”

#===============================================================================

# PHASE 4 — K3s

#===============================================================================
phase “Phase 4 · K3s (Lightweight Kubernetes)”

# ── Kernel tuning (must be before K3s starts) ─────────────────────────────

cat <<EOF > /etc/sysctl.d/99-k3s-incus.conf

# IP forwarding (K3s + Incus networking)

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# inotify (GitOps watchers / Big Bang Flux)

fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288

# conntrack (service mesh)

net.netfilter.nf_conntrack_max = 131072

# Memory overcommit (K3s scheduling)

vm.overcommit_memory = 1

# File descriptors

fs.file-max = 1048576

# Reduce swap pressure — keep workloads in RAM

vm.swappiness = 10
EOF
sysctl –system > /dev/null 2>&1
log “Kernel parameters tuned”

cat <<EOF > /etc/security/limits.d/99-k3s.conf

- soft nofile 65536
- hard nofile 65536
- soft nproc  32768
- hard nproc  32768
  EOF
  log “File descriptor limits raised”

# ── Install K3s (stable channel) ──────────────────────────────────────────

# –disable traefik:    Big Bang uses Istio for ingress

# –disable servicelb:  We’ll use MetalLB for LoadBalancer services

# –write-kubeconfig-mode 644: let non-root read kubeconfig

curl -sfL https://get.k3s.io |   
INSTALL_K3S_CHANNEL=“stable”   
INSTALL_K3S_EXEC=“server   
–disable=traefik   
–disable=servicelb   
–write-kubeconfig-mode=644   
–node-name=${NODE_NAME}   
–tls-san=${PRIMARY_IP}   
–tls-san=${NODE_NAME}”   
sh -
log “K3s server installed (stable channel)”

# ── Wait for API ──────────────────────────────────────────────────────────

log “Waiting for K3s API…”
for i in $(seq 1 90); do
if /usr/local/bin/kubectl get nodes &>/dev/null; then
log “K3s API ready”
break
fi
sleep 2
done

# ── kubectl for non-root user ─────────────────────────────────────────────

mkdir -p “${MAIN_HOME}/.kube”
cp /etc/rancher/k3s/k3s.yaml “${MAIN_HOME}/.kube/config”
sed -i “s/127.0.0.1/${PRIMARY_IP}/” “${MAIN_HOME}/.kube/config”
chown -R “${MAIN_USER}:${MAIN_USER}” “${MAIN_HOME}/.kube”
log “kubeconfig → ~/.kube/config”

# ── kubectl completions ───────────────────────────────────────────────────

/usr/local/bin/kubectl completion bash > /etc/bash_completion.d/kubectl 2>/dev/null || true
log “kubectl bash completion installed”

# ── Helm ──────────────────────────────────────────────────────────────────

curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
log “Helm $(helm version –short 2>/dev/null || echo ‘installed’)”

# ── Flux CLI (Big Bang GitOps) ────────────────────────────────────────────

curl -sL https://fluxcd.io/install.sh | bash
log “Flux CLI installed”

# ── k9s (Kubernetes TUI) ─────────────────────────────────────────────────

wget -qO /tmp/k9s.tar.gz   
“https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz”
tar -C /usr/local/bin -xzf /tmp/k9s.tar.gz k9s
chmod +x /usr/local/bin/k9s
rm -f /tmp/k9s.tar.gz
log “k9s ${K9S_VERSION}”

# ── Node status ───────────────────────────────────────────────────────────

echo “”
/usr/local/bin/kubectl get nodes -o wide 2>/dev/null || warn “K3s still starting”
echo “”

#===============================================================================

# PHASE 5 — MetalLB

#===============================================================================
phase “Phase 5 · MetalLB (Bare-Metal Load Balancer)”

/usr/local/bin/kubectl apply -f   
“https://raw.githubusercontent.com/metallb/metallb/${METALLB_VERSION}/config/manifests/metallb-native.yaml”
log “MetalLB ${METALLB_VERSION} deployed”

# ── Template config for user to customize ─────────────────────────────────

cat <<‘MLBEOF’ > “${MAIN_HOME}/metallb-config.yaml”

# MetalLB IP Address Pool

# ─────────────────────────────────────────────────────────

# Edit the address range to a slice of your LAN that your

# router’s DHCP will NOT assign. Then apply:

# kubectl apply -f ~/metallb-config.yaml

# ─────────────────────────────────────────────────────────

-----

## apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
name: homelab-pool
namespace: metallb-system
spec:
addresses:
- 192.168.1.240-192.168.1.250   # ← CHANGE THIS

apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
name: homelab-l2
namespace: metallb-system
spec:
ipAddressPools:
- homelab-pool
MLBEOF
chown “${MAIN_USER}:${MAIN_USER}” “${MAIN_HOME}/metallb-config.yaml”
log “MetalLB config template → ~/metallb-config.yaml”

#===============================================================================

# PHASE 6 — DEV TOOLS

#===============================================================================
phase “Phase 6 · Dev Tools”

# ── Go ────────────────────────────────────────────────────────────────────

wget -qO /tmp/go.tar.gz “https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz”
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm -f /tmp/go.tar.gz

cat <<‘GOEOF’ > /etc/profile.d/go-path.sh
export PATH=”$PATH:/usr/local/go/bin”
export GOPATH=”$HOME/go”
export PATH=”$PATH:$GOPATH/bin”
GOEOF
log “Go ${GO_VERSION}”

# ── Node.js 22 LTS ───────────────────────────────────────────────────────

curl -fsSL https://deb.nodesource.com/setup_22.x | bash - > /dev/null 2>&1
apt-get install -y -qq nodejs
log “Node.js $(node –version 2>/dev/null || echo ‘22.x’)”

# ── Rust (user-level, non-interactive) ────────────────────────────────────

su - “$MAIN_USER” -c   
‘curl –proto “=https” –tlsv1.2 -sSf https://sh.rustup.rs | sh -s – -y 2>/dev/null’   
|| warn “Rust install deferred — run: curl –proto ‘=https’ –tlsv1.2 -sSf https://sh.rustup.rs | sh”
log “Rust toolchain (user-level)”

# ── VS Code ───────────────────────────────────────────────────────────────

wget -qO- https://packages.microsoft.com/keys/microsoft.asc   
| gpg –dearmor -o /etc/apt/keyrings/microsoft.gpg

cat <<EOF > /etc/apt/sources.list.d/vscode.sources
Enabled: yes
Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/microsoft.gpg
EOF

apt-get update -qq
apt-get install -y -qq code
log “VS Code”

# ── Docker CLI (image builds only — K3s uses containerd at runtime) ───────

apt-get install -y -qq docker.io docker-compose
systemctl disable –now docker.socket docker.service 2>/dev/null || true
usermod -aG docker “$MAIN_USER”
log “Docker CLI (daemon disabled — K3s containerd is the runtime)”

# ── Spotify ───────────────────────────────────────────────────────────────

curl -sS https://download.spotify.com/debian/pubkey_C85668DF69375001.gpg   
| gpg –dearmor –yes -o /etc/apt/keyrings/spotify.gpg
echo “deb [signed-by=/etc/apt/keyrings/spotify.gpg] http://repository.spotify.com stable non-free”   
> /etc/apt/sources.list.d/spotify.list
apt-get update -qq
apt-get install -y -qq spotify-client
log “Spotify”

# ── CLI power tools ───────────────────────────────────────────────────────

apt-get install -y -qq   
fd-find ripgrep bat fzf   
lazygit   
httpie   
shellcheck   
direnv   
sqlite3   
ansible   
dnsmasq   
nfs-kernel-server
log “CLI tools (fd, rg, bat, fzf, lazygit, httpie, shellcheck, direnv, ansible)”

# Disable dnsmasq — configure for PXE later

systemctl disable –now dnsmasq 2>/dev/null || true
log “dnsmasq installed but disabled (PXE provisioning later)”

#===============================================================================

# PHASE 7 — SHELL ENVIRONMENT

#===============================================================================
phase “Phase 7 · Shell Environment”

# ── Oh My Zsh + plugins ──────────────────────────────────────────────────

su - “$MAIN_USER” -c   
‘sh -c “$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)” “” –unattended 2>/dev/null’   
|| warn “Oh My Zsh deferred”

su - “$MAIN_USER” -c ’
ZSH_CUSTOM=”${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}”
git clone -q https://github.com/zsh-users/zsh-autosuggestions “$ZSH_CUSTOM/plugins/zsh-autosuggestions” 2>/dev/null || true
git clone -q https://github.com/zsh-users/zsh-syntax-highlighting “$ZSH_CUSTOM/plugins/zsh-syntax-highlighting” 2>/dev/null || true
’ || true
log “Oh My Zsh + autosuggestions + syntax-highlighting”

# ── Zsh config additions ─────────────────────────────────────────────────

cat <<‘ZSHEOF’ >> “${MAIN_HOME}/.zshrc”

# ─── Homelab ──────────────────────────────────────────────────────────────

# Kubernetes

export KUBECONFIG=”$HOME/.kube/config”
alias k=‘kubectl’
alias kgp=‘kubectl get pods -A’
alias kgs=‘kubectl get svc -A’
alias kgn=‘kubectl get nodes -o wide’
alias kga=‘kubectl get all -A’
alias kctx=‘kubectl config get-contexts’
alias kdesc=‘kubectl describe’
alias klogs=‘kubectl logs -f’
alias kexec=‘kubectl exec -it’
source <(kubectl completion zsh) 2>/dev/null
source <(helm completion zsh) 2>/dev/null

# Incus

alias il=‘incus list’
alias ils=‘incus list -c nsT4’
alias icl=‘incus cluster list’
alias ish=‘incus shell’

# Go

export PATH=”$PATH:/usr/local/go/bin:$HOME/go/bin”

# Rust

[[ -f “$HOME/.cargo/env” ]] && source “$HOME/.cargo/env”

# Aliases

alias ll=‘ls -lah –color=auto’
alias la=‘ls -A –color=auto’
alias ports=‘ss -tulnp’
alias myip=‘hostname -I | awk “{print $1}”’
alias sysinfo=‘fastfetch’
alias dps=‘docker ps –format “table {{.Names}}\t{{.Status}}\t{{.Ports}}”’

# bat alias (Debian names it batcat)

alias bat=‘batcat’

# fd alias (Debian names it fdfind)

alias fd=‘fdfind’

# fzf integration

source /usr/share/doc/fzf/examples/key-bindings.zsh 2>/dev/null
source /usr/share/doc/fzf/examples/completion.zsh 2>/dev/null

# direnv

eval “$(direnv hook zsh)” 2>/dev/null
ZSHEOF

chown “${MAIN_USER}:${MAIN_USER}” “${MAIN_HOME}/.zshrc”
chsh -s /usr/bin/zsh “$MAIN_USER”
log “Zsh set as default shell with homelab aliases”

#===============================================================================

# PHASE 8 — SYSTEM TUNING

#===============================================================================
phase “Phase 8 · System Tuning”

# ── Wake on LAN ───────────────────────────────────────────────────────────

PRIMARY_NIC=$(ip route | awk ‘/default/{print $5; exit}’)
if [[ -n “$PRIMARY_NIC” ]]; then
if ethtool -s “$PRIMARY_NIC” wol g 2>/dev/null; then
cat <<WOLEOF > /etc/systemd/system/wol.service
[Unit]
Description=Enable Wake on LAN on ${PRIMARY_NIC}
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -s ${PRIMARY_NIC} wol g

[Install]
WantedBy=multi-user.target
WOLEOF
systemctl enable wol.service 2>/dev/null
log “Wake on LAN enabled on ${PRIMARY_NIC}”
else
warn “Wake on LAN not supported on ${PRIMARY_NIC}”
fi
fi

#===============================================================================

# PHASE 9 — HYPRLAND PREPARATION

#===============================================================================
phase “Phase 9 · Hyprland (JaKooLit Debian-Hyprland)”

# Pre-install audio + Wayland foundations so JaKooLit runs faster

apt-get install -y -qq   
pipewire pipewire-alsa pipewire-pulse wireplumber   
xwayland   
seatd   
grim slurp wl-clipboard   
thunar thunar-archive-plugin   
sddm   
fonts-noto fonts-font-awesome fonts-noto-color-emoji   
brightnessctl playerctl pamixer   
libnotify-bin dunst

# seatd is needed for non-root Wayland compositors

systemctl enable seatd
usermod -aG video  “$MAIN_USER”
usermod -aG render “$MAIN_USER”
usermod -aG input  “$MAIN_USER”
log “Wayland + audio + seatd pre-installed”

# Clone JaKooLit’s installer

HYPR_DIR=”${MAIN_HOME}/Debian-Hyprland”
if [[ ! -d “$HYPR_DIR” ]]; then
su - “$MAIN_USER” -c   
“git clone –depth=1 https://github.com/JaKooLit/Debian-Hyprland.git ‘${HYPR_DIR}’”   
|| warn “Could not clone JaKooLit — check network”
fi
log “JaKooLit installer → ~/Debian-Hyprland”

#===============================================================================

# PHASE 10 — REFERENCE FILES

#===============================================================================
phase “Phase 10 · Reference Files”

# ── Cluster join cheatsheet ───────────────────────────────────────────────

cat <<‘CHEAT’ > “${MAIN_HOME}/CLUSTER-CHEATSHEET.md”

# Homelab Cluster Cheatsheet

## Add a new Incus node

```bash
# On master: generate a join token
incus cluster add <new-node-name>

# On new node: run incus admin init, paste the token when prompted
```

## Add a K3s worker node

```bash
# Get the node token from master
sudo cat /var/lib/rancher/k3s/server/node-token

# On worker node
curl -sfL https://get.k3s.io | K3S_URL=https://<master-ip>:6443 K3S_TOKEN=<token> sh -
```

## K3s useful commands

```bash
k get nodes -o wide          # Node status
k get pods -A                # All pods all namespaces
k top nodes                  # Resource usage
k9s                          # TUI dashboard
```

## Incus useful commands

```bash
incus list                           # Running instances
incus launch images:debian/13 myvm   # Launch container
incus launch images:debian/13 myvm --vm  # Launch VM
incus shell myvm                     # Get a shell
incus cluster list                   # Cluster members
```

## MetalLB setup

```bash
vim ~/metallb-config.yaml    # Edit IP range first
kubectl apply -f ~/metallb-config.yaml
```

## PXE Boot (future)

```bash
# dnsmasq is installed but disabled
# Configure /etc/dnsmasq.d/pxe.conf then:
sudo systemctl enable --now dnsmasq
```

## Incus Web UI

```
https://<master-ip>:8443
```

## Dual NIC Configuration

```bash
# The N95 has dual GbE. Configure the second NIC for cluster traffic:
# Create /etc/network/interfaces.d/cluster:
#
#   auto enp2s0
#   iface enp2s0 inet static
#       address 10.0.0.1
#       netmask 255.255.255.0
```

CHEAT

chown “${MAIN_USER}:${MAIN_USER}” “${MAIN_HOME}/CLUSTER-CHEATSHEET.md”
log “Cheatsheet → ~/CLUSTER-CHEATSHEET.md”

# ── Verify script ─────────────────────────────────────────────────────────

cat <<‘VERIFY’ > “${MAIN_HOME}/verify-install.sh”
#!/usr/bin/env bash
echo “”
echo “── Installed Versions ──────────────────────────────”
printf “  %-12s %s\n” “OS:”      “$(lsb_release -ds 2>/dev/null || grep PRETTY /etc/os-release | cut -d= -f2 | tr -d ‘”’)”
printf “  %-12s %s\n” “Kernel:”  “$(uname -r)”
printf “  %-12s %s\n” “Incus:”   “$(incus version 2>/dev/null || echo ‘not found’)”
printf “  %-12s %s\n” “K3s:”     “$(k3s –version 2>/dev/null | head -1 || echo ‘not found’)”
printf “  %-12s %s\n” “kubectl:” “$(kubectl version –client 2>/dev/null | grep -oP ‘v[\d.]+’ | head -1 || echo ‘not found’)”
printf “  %-12s %s\n” “Helm:”    “$(helm version –short 2>/dev/null || echo ‘not found’)”
printf “  %-12s %s\n” “Flux:”    “$(flux –version 2>/dev/null || echo ‘not found’)”
printf “  %-12s %s\n” “Go:”      “$(/usr/local/go/bin/go version 2>/dev/null | awk ‘{print $3}’ || echo ‘not found’)”
printf “  %-12s %s\n” “Node.js:” “$(node –version 2>/dev/null || echo ‘not found’)”
printf “  %-12s %s\n” “Rust:”    “$(rustc –version 2>/dev/null | awk ‘{print $2}’ || echo ‘not found’)”
printf “  %-12s %s\n” “Python:”  “$(python3 –version 2>/dev/null | awk ‘{print $2}’ || echo ‘not found’)”
printf “  %-12s %s\n” “Docker:”  “$(docker –version 2>/dev/null | grep -oP ‘[\d.]+’ | head -1 || echo ‘not found’)”
printf “  %-12s %s\n” “k9s:”     “$(k9s version –short 2>/dev/null | head -1 || echo ‘not found’)”
printf “  %-12s %s\n” “Hyprland:” “$(Hyprland –version 2>/dev/null | head -1 || echo ‘not installed yet’)”
echo “───────────────────────────────────────────────────”
echo “”
echo “── K3s Nodes ──”
kubectl get nodes -o wide 2>/dev/null || echo “  (not ready)”
echo “”
echo “── K3s Pods ──”
kubectl get pods -A 2>/dev/null || echo “  (not ready)”
echo “”
echo “── Incus ──”
incus list 2>/dev/null || echo “  (not initialized)”
echo “”
VERIFY

chmod +x “${MAIN_HOME}/verify-install.sh”
chown “${MAIN_USER}:${MAIN_USER}” “${MAIN_HOME}/verify-install.sh”
log “Verification script → ~/verify-install.sh”

#===============================================================================

# DONE

#===============================================================================

ELAPSED=$(( SECONDS - START_TIME ))
MINS=$(( ELAPSED / 60 ))
SECS=$(( ELAPSED % 60 ))

phase “Installation Complete · ${MINS}m ${SECS}s”

cat <<SUMMARY

┌──────────────────────────────────────────────────────────────────┐
│                       MASTER NODE READY                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Host:  ${NODE_NAME}  ·  ${PRIMARY_IP}
│  User:  ${MAIN_USER}
│                                                                  │
│  Incus Web UI   →  https://${PRIMARY_IP}:8443
│  K3s API        →  https://${PRIMARY_IP}:6443
│  SSH            →  ssh ${MAIN_USER}@${PRIMARY_IP}
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NEXT STEPS:                                                     │
│                                                                  │
│  1. sudo reboot                                                  │
│                                                                  │
│  2. Install Hyprland (as your user, not root):                   │
│     cd ~/Debian-Hyprland                                         │
│     chmod +x install.sh                                          │
│     ./install.sh                                                 │
│                                                                  │
│     • Pick SDDM when asked for login manager                    │
│     • Defaults are fine for everything else                      │
│     • Reboot again when done                                     │
│     • At SDDM, select “Hyprland” session                        │
│                                                                  │
│  3. After Hyprland is running:                                   │
│     sudo apt install network-manager-gnome                       │
│                                                                  │
│  4. Configure MetalLB:                                           │
│     vim ~/metallb-config.yaml                                    │
│     kubectl apply -f ~/metallb-config.yaml                       │
│                                                                  │
│  5. Verify everything:                                           │
│     ~/verify-install.sh                                          │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│  FILES:                                                          │
│  ~/metallb-config.yaml        MetalLB IP pool template           │
│  ~/CLUSTER-CHEATSHEET.md      Quick reference                    │
│  ~/verify-install.sh          Version check                      │
│  ~/Debian-Hyprland/           Hyprland installer                 │
│  ~/.kube/config               kubectl config                     │
└──────────────────────────────────────────────────────────────────┘

SUMMARY

warn “Reboot now: sudo reboot”
echo “”
