#!/bin/bash
# ==============================================
# DockShield Final v4 - "Option B" Port Fix
# - Implements "Option B" architecture:
#   - All projects get a high, random, free host port.
#   - Caddy is ONLY used if a public domain is specified.
#   - Stops port 80 conflicts.
# - Fixes the "auto-wrapper" bug by improving project detection.
# - TUI now correctly displays the assigned port.
# ==============================================
set -euo pipefail
IFS=$'\n\t'

# ---------- Config ----------
NEW_USER="dockshield"
SSH_PORT=22
LOGFILE="/var/log/dockshield_deploy.log"
PROJECT_DIR="/opt/dockshield_projects"
DOCKER_NETWORK="dockshield_net"
CADDY_CONTAINER="dockshield_caddy"
CADDYFILE_HOST="/etc/caddy/Caddyfile"
CADDY_VOLUME="caddy_data"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
mkdir -p "$PROJECT_DIR"

log() { echo "$(date -Iseconds) - $*" >> "$LOGFILE"; }
info() { echo -e "${GREEN}$*${NC}"; log "$*"; }
warn() { echo -e "${YELLOW}$*${NC}"; log "WARN: $*"; }
die() { echo -e "${RED}ERROR:${NC} $*"; log "ERROR: $*"; exit 1; }

# ---------- Banner ----------
echo -e "${GREEN}"
cat <<'EOF'
 ____              _      ____  _     _     _     _
|  _ \  ___     ___| | __ / ___|| |__ (_)___| | __| |
| | | |/ _ \ / __| |/ / \___ \| '_ \| |/ _ \ |/ _` |
| |_| | (_) | (__|   <   ___) | | | | |  __/ | (_| |
|____/ \___/ \___|_|\_\|____/|_| |_|_|\___|_|\__,_|
EOF
echo -e "${NC}"
echo -e "${YELLOW}DockShield Final v4 — \"Option B\" Port Fix${NC}"
echo "Log: $LOGFILE"
log "DockShield v4 (Option B) started."

# ---------- Basic checks ----------
if [ "$EUID" -ne 0 ]; then
  die "Please run as root (sudo)."
fi

# OS detection
if grep -qi 'ubuntu' /etc/os-release; then OS="ubuntu"
elif grep -qi 'debian' /etc/os-release; then OS="debian"
elif grep -qi 'centos\|rhel\|fedora' /etc/os-release; then OS="rhel"
else OS="unknown"; fi
info "Detected OS: $OS"
log "OS=$OS"

# ---------- Helpers ----------
wait_for_apt() {
  [ "$OS" != "ubuntu" ] && [ "$OS" != "debian" ] && return
  echo -e "${YELLOW}Waiting for APT lock(s) if present...${NC}"
  local timeout=60 elapsed=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if [ $elapsed -ge $timeout ]; then
      warn "Timeout reached; forcing apt unlock..."
      pkill -9 apt apt-get 2>/dev/null || true
      rm -f /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock || true
      dpkg --configure -a || true
      break
    fi
    sleep 2; elapsed=$((elapsed+2))
  done
}

# sanitize to valid docker image/name fragment (safe, uses underscores)
sanitize_name() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/_/g' \
    | sed 's/_\+/_/g' \
    | sed 's/^_//' | sed 's/_$//'
}

generate_safe_name() {
  local base
  base="$(sanitize_name "$1")"
  [ -z "$base" ] && base="img"
  local name="$base"
  if docker ps -a --format '{{.Names}}' | grep -xq "$name"; then
    name="${base}_$(date +%s)"
  fi
  echo "$name"
}

# check if a port is free (basic)
port_free() {
  local p=$1
  if ss -ltn | awk '{print $4}' | grep -qE "[:.]$p\$"; then
    return 1
  fi
  return 0
}

# Find a free random port
find_free_port() {
  for i in $(shuf -i 10000-65000 -n 50); do
    if port_free "$i"; then
      echo "$i"
      return 0
    fi
  done
  return 1
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1; then
    info "Docker found."
  else
    warn "Docker not found. Installing automatically..."
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
      wait_for_apt
      apt-get update -y
      apt-get install -y ca-certificates curl gnupg lsb-release
      curl -fsSL https://get.docker.com | sh
    else
      die "Please install Docker manually on $OS."
    fi
    info "Docker installed."
  fi
  systemctl enable --now docker
}

ensure_network() {
  if ! docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
    docker network create "$DOCKER_NETWORK"
    info "Created docker network: $DOCKER_NETWORK"
  else
    info "Docker network $DOCKER_NETWORK exists."
  fi
}

# ensure dialog is installed (for TUI)
ensure_dialog() {
  if command -v dialog >/dev/null 2>&1; then
    return 0
  fi
  if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    info "Installing dialog (required for TUI)..."
    wait_for_apt
    apt-get update -y
    apt-get install -y dialog
    return 0
  else
    warn "dialog not installed and auto-install not supported on $OS. TUI will not work."
    return 1
  fi
}

# ---------- Auto Python wrapper generator (server.py + Dockerfile for simple apps) ----------
create_auto_python_wrapper() {
  # $1 = project path
  local p="$1"
  info "Creating auto-python wrapper (server.py + Dockerfile) in $p"
  cat > "$p/server.py" <<'PYWRAP'
from flask import Flask, render_template_string
import subprocess, traceback, os

app = Flask(__name__)

# Run the script ONCE at startup and cache the output
try:
    result = subprocess.check_output(["python", "app.py"], stderr=subprocess.STDOUT, timeout=15)
    CACHED_OUTPUT = result.decode()
except Exception as e:
    CACHED_OUTPUT = "Error running app.py:\n" + traceback.format_exc()

# Try to read the code ONCE at startup
try:
    with open("app.py", "r") as f:
        CACHED_CODE = f.read()
except Exception:
    CACHED_CODE = "Unable to read app.py"


TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>DockShield — App Runner</title>
  <style>
    body{background:#0b1220;color:#e6eef6;font-family:monospace;padding:16px}
    .tabs{display:flex;gap:8px;margin-bottom:12px}
    .tab{padding:6px 12px;background:#112031;border-radius:6px}
    pre{background:#071019;padding:12px;border-radius:8px;white-space:pre-wrap;overflow:auto}
    h1{font-size:18px}
    .meta{color:#9fb3c8;font-size:13px}
  </style>
</head>
<body>
  <h1>DockShield — Auto App Runner</h1>
  <div class="meta">Project auto-wrapped by DockShield. This page shows script output and source.</div>
  <h2>Output (from first run)</h2>
  <pre>{{output}}</pre>
  <h2>Source (app.py)</h2>
  <pre>{{code}}</pre>
</body>
</html>
"""

@app.route("/")
def home():
    # Serve the cached output and code
    return render_template_string(TEMPLATE, output=CACHED_OUTPUT, code=CACHED_CODE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
PYWRAP

  cat > "$p/Dockerfile" <<'PYDF'
FROM python:3.10-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir flask
EXPOSE 80
CMD ["python", "server.py"]
PYDF

  chmod 644 "$p/Dockerfile" "$p/server.py"
  info "Auto-wrapper files created (server.py + Dockerfile)."
}

# ---------- Secure server phases ----------
secure_server() {
  info "[1/9] Secure Server Setup"
  read -r -p "Create a non-root management user '$NEW_USER'? (y/n) [y]: " createu
  createu=${createu:-y}
  if [[ "$createu" =~ ^[Yy]$ ]]; then
    if id "$NEW_USER" &>/dev/null; then
      info "User $NEW_USER already exists. Skipping creation."
    else
      adduser --gecos "" "$NEW_USER"
      usermod -aG sudo "$NEW_USER"
      info "Created user $NEW_USER and added to sudo."
      log "Created user $NEW_USER"
    fi
  else
    warn "Skipping user creation; actions remain root."
  fi

  read -r -p "Add SSH public key for management user now? (y/n) [n]: " addkey
  addkey=${addkey:-n}
  if [[ "$addkey" =~ ^[Yy]$ ]]; then
    read -r -p "Paste SSH public key: " pubkey
    if [ -n "$pubkey" ]; then
      mkdir -p /home/$NEW_USER/.ssh
      echo "$pubkey" > /home/$NEW_USER/.ssh/authorized_keys
      chmod 700 /home/$NEW_USER/.ssh
      chmod 600 /home/$NEW_USER/.ssh/authorized_keys
      chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
      info "SSH key installed for $NEW_USER"
    else
      warn "Empty key; skipping."
    fi
  fi

  SSHD="/etc/ssh/sshd_config"
  cp "$SSHD" "$SSHD.bak_$(date +%s)" 2>/dev/null || true
  sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' "$SSHD" || echo "PermitRootLogin no" >> "$SSHD"

  if [ -f "/home/$NEW_USER/.ssh/authorized_keys" ]; then
    sed -i '/^PasswordAuthentication/s/.*/PasswordAuthentication no/' "$SSHD" || echo "PasswordAuthentication no" >> "$SSHD"
    info "Password authentication disabled (key-based auth enforced)."
  else
    sed -i '/^PasswordAuthentication/s/.*/PasswordAuthentication yes/' "$SSHD" || echo "PasswordAuthentication yes" >> "$SSHD"
    warn "No SSH keys found for $NEW_USER. Password auth temporarily enabled to avoid lockout."
  fi

  sshd -t && systemctl restart sshd
  info "SSH configured and restarted."
  log "secure_server done"
}

configure_firewall() {
  info "[2/9] Firewall Configuration"
  read -r -p "Enter SSH port to allow (default $SSH_PORT): " ip
  [[ "$ip" =~ ^[0-9]+$ ]] && SSH_PORT="$ip"
  if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    wait_for_apt
    apt-get install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSH_PORT"/tcp
    read -r -p "Allow HTTP (80)? (for Caddy/public sites) (y/n) [y]: " ah; ah=${ah:-y}
    [[ "$ah" =~ ^[Yy]$ ]] && ufw allow 80/tcp
    read -r -p "Allow HTTPS (443)? (for Caddy/public sites) (y/n) [y]: " ah2; ah2=${ah2:-y}
    [[ "$ah2" =~ ^[Yy]$ ]] && ufw allow 443/tcp
    ufw --force enable
  else
    yum install -y firewalld || dnf install -y firewalld
    systemctl enable --now firewalld
    firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
    [[ "$ah" =~ ^[Yy]$ ]] && firewall-cmd --permanent --add-service=http
    [[ "$ah2" =~ ^[Yy]$ ]] && firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
  fi
  info "Firewall configured."
  log "configure_firewall done"
}

harden_ssh() {
  info "[3/9] SSH Hardening"
  SSHD="/etc/ssh/sshd_config"
  cp "$SSHD" "$SSHD.bak_hard_$(date +%s)" 2>/dev/null || true
  {
    echo "Port $SSH_PORT"
    echo "MaxAuthTries 3"
    echo "LoginGraceTime 30"
    echo "PermitEmptyPasswords no"
    echo "X11Forwarding no"
  } >> "$SSHD"
  sshd -t && systemctl restart sshd
  info "Installing fail2ban..."
  if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    wait_for_apt; apt-get install -y fail2ban
  else
    yum install -y fail2ban || dnf install -y fail2ban
  fi
  systemctl enable --now fail2ban
  info "SSH hardening complete."
  log "harden_ssh done"
}

install_docker() {
  info "[4all ] Installing Docker & ensuring network"
  ensure_docker
  ensure_network
  info "Docker & network ready."
  log "install_docker done"
}

# ---------- Caddy management ----------
deploy_caddy() {
  info "[5/9] Deploying Caddy (auto HTTPS)"
  ensure_docker
  ensure_network
  if [ ! -f "$CADDYFILE_HOST" ]; then
    mkdir -p "$(dirname "$CADDYFILE_HOST")"
    cat > "$CADDYFILE_HOST" <<'CADDY_DEFAULT'
# DockShield Caddyfile - managed by script
http:// {
  respond "DockShield Caddy - no sites configured" 200
}
CADDY_DEFAULT
    info "Default Caddyfile created."
  fi
  docker volume inspect "$CADDY_VOLUME" >/dev/null 2>&1 || docker volume create "$CADDY_VOLUME"
  if docker ps -q -f "name=^/${CADDY_CONTAINER}$" | grep -q . 2>/dev/null; then
    docker network connect "$DOCKER_NETWORK" "$CADDY_CONTAINER" 2>/dev/null || true
    info "Caddy already running and connected to network."
    return
  fi
  if docker ps -aq -f "name=^/${CADDY_CONTAINER}$" | grep -q . 2>/dev/null; then
    docker rm -f "$CADDY_CONTAINER" 2>/dev/null || true
  fi
  docker run -d --name "$CADDY_CONTAINER" --restart=always \
    -p 80:80 -p 443:443 \
    -v "$CADDYFILE_HOST":/etc/caddy/Caddyfile:ro \
    -v "$CADDY_VOLUME":/data \
    --network "$DOCKER_NETWORK" \
    caddy:latest
  sleep 2
  info "Caddy deployed and listening on ports 80/443."
  log "deploy_caddy done"
}

add_site_to_caddy() {
  local domain="$1"; local target="$2"; local port="${3:-80}"
  [ -z "$domain" -o -z "$target" ] && die "add_site_to_caddy requires domain and target"
  if grep -qF "$domain" "$CADDYFILE_HOST"; then
    info "Domain $domain already present in Caddyfile."
    return
  fi
  cat >> "$CADDYFILE_HOST" <<CADDY_ENTRY

$domain {
    reverse_proxy $target:$port
}
CADDY_ENTRY
  info "Appended $domain -> $target:$port to Caddyfile."
  if docker ps -q -f "name=^/${CADDY_CONTAINER}$" | grep -q . 2>/dev/null; then
    docker restart "$CADDY_CONTAINER"
    sleep 2
    info "Caddy restarted."
  else
    warn "Caddy not running; deploying now."
    deploy_caddy
  fi
  log "add_site_to_caddy $domain -> $target:$port"
}

# ---------- Backups & updates ----------
setup_backups() {
  info "[6/9] Setting up backups"
  read -r -p "Enable daily backups (etc + home) at 02:00? (y/n) [n]: " b; b=${b:-n}
  [[ ! "$b" =~ ^[Yy]$ ]] && { info "Backups skipped"; return; }
  BACKUP_DIR="/var/backups/dockshield"
  mkdir -p "$BACKUP_DIR"
  cat > /usr/local/bin/dockshield_backup.sh <<'EOF'
#!/bin/bash
tar -czf /var/backups/dockshield/backup_$(date +%F).tar.gz /etc /home || true
find /var/backups/dockshield/ -type f -mtime +7 -delete || true
EOF
  chmod +x /usr/local/bin/dockshield_backup.sh
  echo "0 2 * * * root /usr/local/bin/dockshield_backup.sh" > /etc/cron.d/dockshield_backup
  info "Backups scheduled at 02:00 daily."
  log "setup_backups done"
}

enable_auto_updates() {
  info "[7/9] Enabling automatic security updates"
  if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    wait_for_apt
    apt-get install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades || true
  else
    yum install -y dnf-automatic || dnf install -y dnf-automatic || true
    systemctl enable --now dnf-automatic.timer || true
  fi
  info "Auto-updates enabled."
  log "enable_auto_updates done"
}

deploy_sample_container() {
  info "[8/9] Deploy sample container"
  echo "1) Nginx (on high random port)"
  echo "2) Portainer (9443/8000)"
  echo "3) Ubuntu (sleep infinity, exec into it to use shell)"
  echo "4) Skip"
  read -r -p "Choose: " ch
  case "$ch" in
    1)
      cname=$(generate_safe_name "nginx")
      HOST_PORT=$(find_free_port) || { warn "Failed to find free port"; return; }
      docker run -d --name "$cname" --network "$DOCKER_NETWORK" -p "${HOST_PORT}:80" nginx
      info "Nginx deployed as $cname on host port $HOST_PORT"
      ;;
    2) deploy_portainer ;;
    3)
      cname=$(generate_safe_name "ubuntu")
      docker run -d --name "$cname" --network "$DOCKER_NETWORK" ubuntu:22.04 sleep infinity
      info "Ubuntu container $cname is running (use 'docker exec -it $cname bash' to enter)."
      ;;
    *) info "Skipped sample deploy" ;;
  esac
}

deploy_portainer() {
  info "Deploying Portainer (if missing)"
  if docker ps -q -f name=portainer >/dev/null 2>&1 && [ -n "$(docker ps -q -f name=portainer)" ]; then
    info "Portainer already running."
    docker network connect "$DOCKER_NETWORK" portainer 2>/dev/null || true
    return
  fi
  if docker ps -aq -f name=portainer >/dev/null 2>&1 && [ -n "$(docker ps -aq -f name=portainer)" ]; then
    docker start portainer
    docker network connect "$DOCKER_NETWORK" portainer 2>/dev/null || true
    info "Started existing Portainer."
    return
  fi
  docker volume create portainer_data >/dev/null 2>&1 || true
  docker run -d --name portainer --restart=always \
    -p 9443:9443 -p 8000:8000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --network "$DOCKER_NETWORK" \
    portainer/portainer-ce:latest
  info "Portainer deployed (9443/8000)."
  log "deploy_portainer done"
}

# ---------- [FIXED] Detect project type helper ----------
detect_project_type() {
  local p="$1"
  
  # 1. Check for Python requirements first (most specific)
  if [ -f "$p/requirements.txt" ]; then
    if grep -qi "django" "$p/requirements.txt" 2>/dev/null; then echo "django"; return; fi
    if grep -qi "fastapi" "$p/requirements.txt" 2>/dev/null; then echo "fastapi"; return; fi
    if grep -qi "flask" "$p/requirements.txt" 2>/dev/null; then echo "flask"; return; fi
  fi
  if [ -f "$p/pyproject.toml" ]; then
    if grep -qi "fastapi" "$p/pyproject.toml" 2>/dev/null; then echo "fastapi"; return; fi
  fi
  
  # 2. Check for other common frameworks
  if [ -f "$p/package.json" ]; then
    if grep -qi '"react"' "$p/package.json" 2>/dev/null || grep -qi '"vite"' "$p/package.json" 2>/dev/null; then
      echo "frontend"
    else
      echo "node"
    fi
    return
  fi
  
  if [ -f "$p/manage.py" ]; then echo "django"; return; fi
  if [ -f "$p/artisan" ] || [ -f "$p/composer.json" ]; then echo "laravel"; return; fi
  if [ -f "$p/main.go" ] || ls "$p"/*.go >/dev/null 2>&1; then echo "go"; return; fi
  if [ -f "$p/Cargo.toml" ]; then echo "rust"; return; fi

  # 3. [FIXED] Only if no other indicators, check for app.py (simple script)
  if [ -f "$p/app.py" ]; then
    echo "simple-python"
    return
  fi

  echo "unknown"
}

# ---------- [FIXED] TUI (dialog) - Now accepts HOST_PORT ----------
show_tabs_ui() {
  local project_path="$1"
  local container_name="$2"
  local host_port="$3"

  # ensure dialog
  ensure_dialog >/dev/null 2>&1 || { warn "dialog not available; skipping TUI."; return; }

  local title="Project Dashboard (Running on Port $host_port)"
  if [ -z "$host_port" ]; then
    title="Project Dashboard (Compose)"
  fi

  while true; do
    CHOICE=$(dialog --clear --backtitle "DockShield UI" \
      --title "$title" \
      --menu "Select a tab:" 15 60 6 \
      1 "Output (container logs snapshot)" \
      2 "View Code (read-only)" \
      3 "Logs (docker logs snapshot)" \
      0 "Back to main menu" \
      --stdout 2>/dev/null) || CHOICE=0

    case "$CHOICE" in
      1)
        # Snapshot of last 200 lines of container logs
        TMP="$(mktemp)"
        docker logs --tail 200 "$container_name" > "$TMP" 2>&1 || echo "No logs (container may not be running)" > "$TMP"
        dialog --backtitle "Output" --title "Container: $container_name - Output (last 200 lines)" --textbox "$TMP" 25 100
        rm -f "$TMP"
        ;;
      2)
        # Try to find a readable file: app.py or list files
        if [ -f "$project_path/app.py" ]; then
          dialog --backtitle "Code Viewer" --title "app.py (read-only)" --textbox "$project_path/app.py" 25 100
        elif [ -f "$project_path/main.py" ]; then
          dialog --backtitle "Code Viewer" --title "main.py (read-only)" --textbox "$project_path/main.py" 25 100
        else
          TMP2="$(mktemp)"
          ls -la "$project_path" > "$TMP2"
          dialog --backtitle "Code Viewer" --title "Project files" --textbox "$TMP2" 25 100
          rm -f "$TMP2"
        fi
        ;;
      3)
        TMP3="$(mktemp)"
        docker logs --tail 200 "$container_name" > "$TMP3" 2>&1 || echo "No logs available" > "$TMP3"
        dialog --backtitle "Docker Logs" --title "Docker Logs (last 200 lines)" --textbox "$TMP3" 25 100
        rm -f "$TMP3"
        ;;
      0)
        break
        ;;
      *)
        break
        ;;
    esac
  done
}

# ---------- [FIXED] Run project (implements Option B) ----------
run_project() {
  info "[9/9] Run user project (Git or Local)"
  echo "1) Clone from Git"
  echo "2) Use local path"
  read -r -p "Choice (1/2): " choice
  if [ "$choice" = "1" ]; then
    read -r -p "Git repo URL: " GIT_URL
    [ -z "$GIT_URL" ] && { warn "No URL"; return; }
    cd "$PROJECT_DIR"
    git clone "$GIT_URL" || { warn "git clone failed"; return; }
    proj="$(basename "$GIT_URL" .git)"
    PROJECT_PATH="$PROJECT_DIR/$proj"
    info "Cloned to $PROJECT_PATH"
  elif [ "$choice" = "2" ]; then
    read -r -p "Full local path (e.g. /home/ishan/Desktop/Test): " PROJECT_PATH
    [ -z "$PROJECT_PATH" ] && { warn "No path"; return; }
    if [ ! -d "$PROJECT_PATH" ]; then warn "Directory not found: $PROJECT_PATH"; return; fi
  else
    warn "Invalid choice"; return
  fi

  cd "$PROJECT_PATH" || { warn "Cannot cd to project"; return; }

  echo -e "${YELLOW}Detected files:${NC}"
  [ -f docker-compose.yml ] && echo " - docker-compose.yml"
  [ -f docker-compose.yaml ] && echo " - docker-compose.yaml"
  [ -f Dockerfile ] && echo " - Dockerfile"
  echo ""

  read -r -p "Expose via PUBLIC domain? (e.g. my-app.com) (leave empty for local-only port): " PROJECT_DOMAIN
  if [ -n "$PROJECT_DOMAIN" ]; then
    warn "Ensure DNS A record for $PROJECT_DOMAIN points to this server's public IP!"
    read -r -p "Proceed to add Caddy mapping for $PROJECT_DOMAIN? (y/n) [y]: " ok; ok=${ok:-y}
    [[ ! "$ok" =~ ^[Yy]$ ]] && { info "Skipping domain mapping"; PROJECT_DOMAIN=""; }
  fi

  # If docker-compose present -> use compose
  if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
    info "Using docker compose..."
    docker compose up -d || { warn "docker compose up failed"; return; }
    sleep 2
    echo "Listing containers started (top 20):"
    docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' | head -n 20
    read -r -p "Enter exact container name to proxy (or leave empty to skip): " TARGET_CONTAINER
    if [ -n "$TARGET_CONTAINER" ]; then
      docker network connect "$DOCKER_NETWORK" "$TARGET_CONTAINER" 2>/dev/null || true
      read -r -p "Internal port the container listens on (default 80): " TARGET_PORT; TARGET_PORT=${TARGET_PORT:-80}
      if [ -n "$PROJECT_DOMAIN" ]; then
        add_site_to_caddy "$PROJECT_DOMAIN" "$TARGET_CONTAINER" "$TARGET_PORT"
        info "Mapped https://$PROJECT_DOMAIN -> $TARGET_CONTAINER:$TARGET_PORT"
      else
        info "Project deployed but not proxied (no domain provided)."
      fi
    else
      info "No container selected; compose project deployed without proxy."
    fi
    return
  fi

  # If Dockerfile present or not, we may need to generate one
  project_type=$(detect_project_type "$PROJECT_PATH")
  info "Detected project type: $project_type"

  # If Dockerfile missing, offer to generate
  if [ ! -f Dockerfile ]; then
    if [ "$project_type" = "simple-python" ]; then
      read -r -p "No Dockerfile found, but app.py exists. Generate auto-wrapper to serve it? (y/n) [y]: " gen2; gen2=${gen2:-y}
      if [[ "$gen2" =~ ^[Yy]$ ]]; then
        create_auto_python_wrapper "$PROJECT_PATH"
      else
        warn "Aborting (no Dockerfile)"; return
      fi
    elif [ "$project_type" != "unknown" ]; then
      read -r -p "No Dockerfile found. Generate a recommended Dockerfile for '$project_type'? (y/n) [y]: " gen; gen=${gen:-y}
      if [[ "$gen" =~ ^[Yy]$ ]]; then
        create_dockerfile_for_type "$project_type" "$PROJECT_PATH" || warn "Failed to create Dockerfile template"
      else
         warn "Aborting (no Dockerfile)"; return
      fi
    else
      warn "No Dockerfile, docker-compose, or recognizable project type found. Aborting."
      return
    fi
  fi

  # After this point, we must have a Dockerfile
  if [ -f Dockerfile ]; then
    base="$(basename "$PROJECT_PATH")"
    img_base="$(sanitize_name "$base")"
    IMAGE_TAG="${img_base}_img"
    
    info "Building image: $IMAGE_TAG"
    if docker build -t "$IMAGE_TAG" .; then
      info "Build OK"
    else
      warn "docker build failed"; return
    fi

    case "$project_type" in
      node) DEFAULT_INT=3000 ;;
      django) DEFAULT_INT=8000 ;;
      fastapi|flask) DEFAULT_INT=8000 ;;
      frontend) DEFAULT_INT=80 ;;
      laravel) DEFAULT_INT=8000 ;;
      go) DEFAULT_INT=8080 ;;
      rust) DEFAULT_INT=8080 ;;
      simple-python) DEFAULT_INT=80 ;; # The wrapper runs on 80
      *) DEFAULT_INT=80 ;;
    esac

    read -r -p "Container internal port (inside container) [${DEFAULT_INT}]: " INTERNAL_PORT; INTERNAL_PORT=${INTERNAL_PORT:-$DEFAULT_INT}
    
    # [FIXED] Find a random free port (Option B)
    HOST_PORT=$(find_free_port) || { warn "Failed to find a free port to run this container on"; return; }
    info "Found free port: $HOST_PORT"

    CONTAINER_NAME=$(generate_safe_name "$base")
    docker run -d --name "$CONTAINER_NAME" --network "$DOCKER_NETWORK" -p "${HOST_PORT}:${INTERNAL_PORT}" "$IMAGE_TAG" || { warn "docker run failed"; return; }

    # [FIXED] Clearer output
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${GREEN}  APP IS RUNNING!${NC}"
    info "  Container: $CONTAINER_NAME"
    info "  Access at: http://<your-server-IP>:$HOST_PORT"
    info "  (Port 80/443 is Caddy. Your app is on port $HOST_PORT)"
    echo -e "${CYAN}============================================================${NC}"

    # If domain was requested, map it via Caddy
    if [ -n "$PROJECT_DOMAIN" ]; then
      add_site_to_caddy "$PROJECT_DOMAIN" "$CONTAINER_NAME" "$INTERNAL_PORT"
      info "Mapped public domain https://$PROJECT_DOMAIN -> $CONTAINER_NAME:$INTERNAL_PORT"
    fi

    # [FIXED] Pass the host port to the TUI
    ensure_dialog
    show_tabs_ui "$PROJECT_PATH" "$CONTAINER_NAME" "$HOST_PORT"

    return
  fi

  warn "No docker-compose.yml or Dockerfile found (and no generation chosen)."
}

# ---------- Simple Dockerfile generator for common types ----------
create_dockerfile_for_type() {
  local type="$1"; local p="$2"
  local df="$p/Dockerfile"
  case "$type" in
    node)
      cat > "$df" <<'NODE_DF'
# Node.js production Dockerfile (multi-stage)
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
FROM node:18-alpine
WORKDIR /app
COPY --from=build /app /app
EXPOSE 3000
CMD ["node", "index.js"]
NODE_DF
      ;;
    frontend)
      cat > "$df" <<'FRONT_DF'
# React / Vite production Dockerfile (build then serve via nginx)
FROM node:18 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM nginx:stable-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
FRONT_DF
      ;;
    django)
      cat > "$df" <<'DJ_DF'
# Django (gunicorn) Dockerfile (best-effort)
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# IMPORTANT: Change 'project.wsgi' to your project's wsgi file
CMD ["gunicorn", "project.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
DJ_DF
      warn "Generated Django Dockerfile. YOU MUST EDIT 'project.wsgi:application' inside the Dockerfile to match your project!"
      ;;
    fastapi)
      cat > "$df" <<'FAST_DF'
# FastAPI (uvicorn) Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# IMPORTANT: Change 'main:app' to your file:app_variable
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
FAST_DF
      warn "Generated FastAPI Dockerfile. Check that 'main:app' is correct!"
      ;;
    flask)
      cat > "$df" <<'FLASK_DF'
# Flask Dockerfile (best-effort)
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# IMPORTANT: Change 'app:app' to your file:app_variable
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
FLASK_DF
      warn "Generated Flask Dockerfile. Check that 'app:app' is correct!"
      ;;
    laravel)
      cat > "$df" <<'LARA_DF'
# Laravel quick Dockerfile (development, best-effort)
FROM php:8.1-fpm
WORKDIR /var/www/html
RUN apt-get update && apt-get install -y git unzip libzip-dev
COPY . .
EXPOSE 9000
CMD ["php-fpm"]
LARA_DF
      ;;
    go)
      cat > "$df" <<'GO_DF'
# Go Dockerfile (build + run)
FROM golang:1.20 AS build
WORKDIR /app
COPY . .
RUN go build -o app
FROM scratch
COPY --from=build /app/app /app
EXPOSE 8080
CMD ["/app"]
GO_DF
      ;;
    rust)
      cat > "$df" <<'RUST_DF'
# Rust Dockerfile (best-effort)
FROM rust:1.70 as build
WORKDIR /app
COPY . .
RUN cargo build --release
FROM debian:bookworm-slim
# IMPORTANT: Change '<binary>' to your app's binary name
COPY --from=build /app/target/release/<binary> /usr/local/bin/app
EXPOSE 8080
CMD ["/usr/local/bin/app"]
RUST_DF
      warn "Generated Rust Dockerfile. YOU MUST EDIT '<binary>' to your app's binary name!"
      ;;
    *)
      return 1
      ;;
  esac
  chmod 644 "$df"
  info "Generated Dockerfile at $df for type $type"
  return 0
}

# ---------- Maintenance ----------
list_containers() { docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"; }
remove_named() { read -r -p "Container name to remove: " cn; docker rm -f "$cn" || warn "Failed to remove $cn"; }
cleanup() { docker system prune -af; docker volume prune -f; info "Cleaned Docker."; }

# ---------- Interactive menu ----------
while true; do
  cat <<MENU

${CYAN}DockShield Final v4 — "Option B" Port Fix${NC}
1) Secure server setup (create user / SSH keys)
2) Configure firewall (UFW / firewalld)
3) Harden SSH & install Fail2Ban
4) Install Docker & ensure dockshield network
5) Deploy Caddy reverse proxy (auto-HTTPS)
6) Deploy Portainer (optional)
7) Setup Backups (daily)
8) Enable Auto Updates
9) Deploy sample container (nginx/portainer/ubuntu)
10) Run your project (Git clone or Local path)
11) List running containers
12) Remove named container
13) Cleanup Docker system
0) Exit

MENU
  read -r -p "Enter choice: " CH
  case "$CH" in
    1) secure_server ;;
    2) configure_firewall ;;
    3) harden_ssh ;;
    4) install_docker ;;
    5) deploy_caddy ;;
    6) deploy_portainer ;;
    7) setup_backups ;;
    8) enable_auto_updates ;;
    9) deploy_sample_container ;;
    10) run_project ;;
    11) list_containers ;;
    12) remove_named ;;
    13) cleanup ;;
    0) info "Exiting. Keep your server secure."; exit 0 ;;
    *) warn "Invalid option." ;;
  esac
done
