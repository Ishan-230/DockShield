#!/bin/bash

# ============================
# DockShield - Automated Secure Server Deployment with Docker Integration
# ============================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOGFILE="/var/log/dockshield_deploy.log"

echo -e "${GREEN}=== DockShield: Starting Automated Secure Server Deployment ===${NC}"
echo "$(date -Iseconds) - Starting DockShield" >> "$LOGFILE"

# --- Check Root Privileges ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo).${NC}"
    exit 1
fi

# --- Detect OS ---
if [ -f /etc/debian_version ]; then
    OS="Debian"
elif [ -f /etc/redhat-release ]; then
    OS="RHEL"
else
    echo -e "${RED}Unsupported OS. DockShield supports Debian/Ubuntu & RHEL/CentOS.${NC}"
    exit 1
fi
echo -e "${YELLOW}Detected OS: $OS${NC}"
echo "$(date -Iseconds) - Detected OS: $OS" >> "$LOGFILE"

# --- Phase 1: Secure Server Setup ---
secure_server() {
    echo -e "${GREEN}[1/8] Setting up secure user...${NC}"
    echo "$(date -Iseconds) - Phase1: secure_user start" >> "$LOGFILE"

    NEW_USER="dockshield"

    # Create user if not exists
    if id "$NEW_USER" &>/dev/null; then
        echo -e "${YELLOW}User '$NEW_USER' already exists. Skipping creation...${NC}"
        echo "$(date -Iseconds) - User $NEW_USER exists" >> "$LOGFILE"
    else
        adduser --gecos "" "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        echo -e "${GREEN}User '$NEW_USER' created and added to sudo group.${NC}"
        echo "$(date -Iseconds) - User $NEW_USER created and added to sudo" >> "$LOGFILE"
    fi

    # Setup SSH keys for new user (copy from root if present)
    if [ ! -d "/home/$NEW_USER/.ssh" ]; then
        mkdir -p /home/$NEW_USER/.ssh
        chmod 700 /home/$NEW_USER/.ssh
    fi

    if [ -f "/root/.ssh/authorized_keys" ]; then
        cp /root/.ssh/authorized_keys /home/$NEW_USER/.ssh/authorized_keys
        chmod 600 /home/$NEW_USER/.ssh/authorized_keys
        chown -R "$NEW_USER":"$NEW_USER" /home/$NEW_USER/.ssh
        echo -e "${GREEN}SSH key copied to '$NEW_USER'.${NC}"
        echo "$(date -Iseconds) - SSH key copied to $NEW_USER" >> "$LOGFILE"
    else
        echo -e "${YELLOW}No root authorized_keys found. You'll need to set up SSH manually for '$NEW_USER'.${NC}"
        echo "$(date -Iseconds) - No root authorized_keys found" >> "$LOGFILE"
    fi

    # Disable root SSH login
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    else
        echo "PermitRootLogin no" >> "$SSHD_CONFIG"
    fi

    # Optionally enforce key-based authentication (ask user)
    read -r -p "$(echo -e "${YELLOW}Do you want to enforce key-based SSH authentication only? (y/n): ${NC}")" ENFORCE_KEYS
    if [[ "$ENFORCE_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
        else
            echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
        fi
        echo "$(date -Iseconds) - Enforced key-based SSH authentication" >> "$LOGFILE"
    fi

    # Restart SSH service (service name differs)
    if [ "$OS" == "Debian" ]; then
        systemctl restart ssh || systemctl restart ssh.service
    else
        systemctl restart sshd || systemctl restart sshd.service
    fi

    echo -e "${GREEN}Root SSH login disabled and SSH configured.${NC}"
    echo "$(date -Iseconds) - Phase1 complete" >> "$LOGFILE"
}

# --- Phase 2: Firewall Configuration ---
configure_firewall() {
    echo -e "${GREEN}[2/8] Configuring firewall...${NC}"
    echo "$(date -Iseconds) - Phase2: firewall start" >> "$LOGFILE"

    # Default ports
    SSH_PORT=22
    ALLOW_HTTP="n"
    ALLOW_HTTPS="n"

    read -r -p "$(echo -e "${YELLOW}Enter SSH port to allow (default 22): ${NC}")" INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" ]]; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi

    read -r -p "$(echo -e "${YELLOW}Allow HTTP (port 80)? (y/n, default n): ${NC}")" ALLOW_HTTP
    read -r -p "$(echo -e "${YELLOW}Allow HTTPS (port 443)? (y/n, default n): ${NC}")" ALLOW_HTTPS

    if [ "$OS" == "Debian" ]; then
        # Install ufw if missing
        if ! command -v ufw &>/dev/null; then
            echo -e "${YELLOW}ufw not found. Installing ufw...${NC}"
            apt-get update && apt-get install -y ufw
            echo "$(date -Iseconds) - ufw installed" >> "$LOGFILE"
        fi

        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing

        # Allow SSH (on provided port)
        ufw allow "$SSH_PORT"/tcp
        echo "$(date -Iseconds) - Allowed SSH port $SSH_PORT/tcp" >> "$LOGFILE"

        # Allow HTTP/HTTPS if requested
        if [[ "$ALLOW_HTTP" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ufw allow 80/tcp
            echo "$(date -Iseconds) - Allowed HTTP (80)" >> "$LOGFILE"
        fi
        if [[ "$ALLOW_HTTPS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ufw allow 443/tcp
            echo "$(date -Iseconds) - Allowed HTTPS (443)" >> "$LOGFILE"
        fi

        # Enable ufw (if not enabled)
        if ufw status | grep -q "Status: active"; then
            echo -e "${YELLOW}ufw already active.${NC}"
            echo "$(date -Iseconds) - ufw already active" >> "$LOGFILE"
        else
            echo -e "${YELLOW}Enabling ufw...${NC}"
            ufw --force enable
            echo "$(date -Iseconds) - ufw enabled" >> "$LOGFILE"
        fi

    else
        # RHEL/CentOS path: use firewalld
        if ! command -v firewall-cmd &>/dev/null; then
            echo -e "${YELLOW}firewalld not found. Installing firewalld...${NC}"
            if command -v yum &>/dev/null; then
                yum install -y firewalld
            elif command -v dnf &>/dev/null; then
                dnf install -y firewalld
            fi
            systemctl enable --now firewalld
            echo "$(date -Iseconds) - firewalld installed and started" >> "$LOGFILE"
        fi

        # Set default zone rules: allow outgoing, remove unwanted
        firewall-cmd --permanent --remove-service=ftp 2>/dev/null || true

        # Allow SSH on selected port
        firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
        echo "$(date -Iseconds) - Allowed SSH port $SSH_PORT/tcp (firewalld)" >> "$LOGFILE"

        if [[ "$ALLOW_HTTP" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            firewall-cmd --permanent --add-service=http
            echo "$(date -Iseconds) - Allowed HTTP (firewalld)" >> "$LOGFILE"
        fi
        if [[ "$ALLOW_HTTPS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            firewall-cmd --permanent --add-service=https
            echo "$(date -Iseconds) - Allowed HTTPS (firewalld)" >> "$LOGFILE"
        fi

        # Reload to apply
        firewall-cmd --reload
        echo "$(date -Iseconds) - firewalld reloaded" >> "$LOGFILE"
    fi

    echo -e "${GREEN}Firewall configuration complete.${NC}"
    echo "$(date -Iseconds) - Phase2 complete" >> "$LOGFILE"
}

# --- Phase 3: SSH Hardening ---
harden_ssh() {
    echo -e "${GREEN}[3/8] Hardening SSH configuration...${NC}"
    echo "$(date -Iseconds) - Phase3: harden_ssh start" >> "$LOGFILE"

    # Backup original sshd_config
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    echo "$(date -Iseconds) - Backed up sshd_config" >> "$LOGFILE"

    # If custom configs/sshd_config exists, use it
    if [ -f "configs/sshd_config" ]; then
        cp configs/sshd_config "$SSHD_CONFIG"
        echo "$(date -Iseconds) - Copied custom sshd_config" >> "$LOGFILE"
    else
        # Otherwise, apply hardcoded hardenings
        # Set Port if changed
        if [ "$SSH_PORT" != "22" ]; then
            if grep -q "^Port" "$SSHD_CONFIG"; then
                sed -i "s/^Port.*/Port $SSH_PORT/" "$SSHD_CONFIG"
            else
                echo "Port $SSH_PORT" >> "$SSHD_CONFIG"
            fi
            echo "$(date -Iseconds) - Set SSH Port to $SSH_PORT" >> "$LOGFILE"
        fi

        # PubkeyAuthentication yes
        if grep -q "^PubkeyAuthentication" "$SSHD_CONFIG"; then
            sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
        else
            echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
        fi

        # MaxAuthTries 4
        if grep -q "^MaxAuthTries" "$SSHD_CONFIG"; then
            sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' "$SSHD_CONFIG"
        else
            echo "MaxAuthTries 4" >> "$SSHD_CONFIG"
        fi

        # LoginGraceTime 30
        if grep -q "^LoginGraceTime" "$SSHD_CONFIG"; then
            sed -i 's/^LoginGraceTime.*/LoginGraceTime 30/' "$SSHD_CONFIG"
        else
            echo "LoginGraceTime 30" >> "$SSHD_CONFIG"
        fi

        # AllowUsers $NEW_USER
        if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
            sed -i "s/^AllowUsers.*/AllowUsers $NEW_USER/" "$SSHD_CONFIG"
        else
            echo "AllowUsers $NEW_USER" >> "$SSHD_CONFIG"
        fi
    fi

    # Restart SSH
    if [ "$OS" == "Debian" ]; then
        systemctl restart ssh || systemctl restart ssh.service
    else
        systemctl restart sshd || systemctl restart sshd.service
    fi
    echo "$(date -Iseconds) - SSH restarted" >> "$LOGFILE"

    # Install fail2ban
    echo -e "${YELLOW}Installing fail2ban for intrusion prevention...${NC}"
    if [ "$OS" == "Debian" ]; then
        apt-get update && apt-get install -y fail2ban
    else
        if command -v yum &>/dev/null; then
            yum install -y fail2ban
        elif command -v dnf &>/dev/null; then
            dnf install -y fail2ban
        fi
    fi
    systemctl enable fail2ban
    systemctl start fail2ban
    echo "$(date -Iseconds) - fail2ban installed and started" >> "$LOGFILE"

    echo -e "${GREEN}SSH hardening complete.${NC}"
    echo "$(date -Iseconds) - Phase3 complete" >> "$LOGFILE"
}

# --- Phase 4: Install Docker ---
install_docker() {
    echo -e "${GREEN}[4/8] Installing Docker...${NC}"
    echo "$(date -Iseconds) - Phase4: install_docker start" >> "$LOGFILE"

    if command -v docker &>/dev/null; then
        echo -e "${YELLOW}Docker already installed. Skipping...${NC}"
        echo "$(date -Iseconds) - Docker already installed" >> "$LOGFILE"
        return
    fi

    if [ "$OS" == "Debian" ]; then
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
        curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        if command -v yum &>/dev/null; then
            yum install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        elif command -v dnf &>/dev/null; then
            dnf install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        fi
    fi

    systemctl start docker
    systemctl enable docker
    usermod -aG docker "$NEW_USER"
    echo "$(date -Iseconds) - Docker installed, user added to group" >> "$LOGFILE"

    echo -e "${GREEN}Docker installation complete.${NC}"
    echo "$(date -Iseconds) - Phase4 complete" >> "$LOGFILE"
}

# --- Phase 5: SSL Setup ---
setup_ssl() {
    echo -e "${GREEN}[5/8] Setting up SSL certificates...${NC}"
    echo "$(date -Iseconds) - Phase5: setup_ssl start" >> "$LOGFILE"

    read -r -p "$(echo -e "${YELLOW}Do you want to set up SSL with Let's Encrypt? (y/n, default n): ${NC}")" SETUP_SSL
    if ! [[ "$SETUP_SSL" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Skipping SSL setup.${NC}"
        echo "$(date -Iseconds) - Skipped SSL setup" >> "$LOGFILE"
        echo "$(date -Iseconds) - Phase5 complete" >> "$LOGFILE"
        return
    fi

    read -r -p "$(echo -e "${YELLOW}Enter your domain name: ${NC}")" DOMAIN
    read -r -p "$(echo -e "${YELLOW}Enter your email for Let's Encrypt: ${NC}")" EMAIL

    # Install certbot
    if [ "$OS" == "Debian" ]; then
        apt-get update && apt-get install -y certbot
    else
        if command -v yum &>/dev/null; then
            yum install -y certbot
        elif command -v dnf &>/dev/null; then
            dnf install -y certbot
        fi
    fi

    # Run certbot standalone (requires port 80 open)
    certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN"
    echo "$(date -Iseconds) - SSL setup for $DOMAIN" >> "$LOGFILE"

    echo -e "${GREEN}SSL setup complete. Certificates are in /etc/letsencrypt/live/$DOMAIN${NC}"
    echo "$(date -Iseconds) - Phase5 complete" >> "$LOGFILE"
}

# --- Phase 6: Setup Backups ---
setup_backups() {
    echo -e "${GREEN}[6/8] Setting up daily backups...${NC}"
    echo "$(date -Iseconds) - Phase6: setup_backups start" >> "$LOGFILE"

    # Install rsync if not present
    if ! command -v rsync &>/dev/null; then
        echo -e "${YELLOW}rsync not found. Installing rsync...${NC}"
        if [ "$OS" == "Debian" ]; then
            apt-get update && apt-get install -y rsync
        else
            if command -v yum &>/dev/null; then
                yum install -y rsync
            elif command -v dnf &>/dev/null; then
                dnf install -y rsync
            fi
        fi
        echo "$(date -Iseconds) - rsync installed" >> "$LOGFILE"
    fi

    # Create backups directory
    mkdir -p /backups

    # Simple daily cron job to backup /home using rsync
    BACKUP_DIR="/backups/home_backup_$(date +%Y%m%d)"
    CRON_JOB="0 2 * * * root rsync -a --delete /home/ $BACKUP_DIR 2>> /var/log/backup.log"
    echo "$CRON_JOB" > /etc/cron.d/dockshield-backup

    echo "$(date -Iseconds) - Daily backup cron job set for /home using rsync" >> "$LOGFILE"

    echo -e "${GREEN}Backups setup complete. Backups will run daily at 2 AM.${NC}"
    echo "$(date -Iseconds) - Phase6 complete" >> "$LOGFILE"
}

# --- Phase 7: Setup Auto Updates ---
setup_auto_updates() {
    echo -e "${GREEN}[7/8] Setting up automatic security updates...${NC}"
    echo "$(date -Iseconds) - Phase7: setup_auto_updates start" >> "$LOGFILE"

    if [ "$OS" == "Debian" ]; then
        apt-get update && apt-get install -y unattended-upgrades
        # Enable security updates
        dpkg-reconfigure -f noninteractive unattended-upgrades
        echo "$(date -Iseconds) - Unattended-upgrades installed and configured" >> "$LOGFILE"
    else
        if command -v yum &>/dev/null; then
            yum install -y yum-cron
        elif command -v dnf &>/dev/null; then
            dnf install -y dnf-automatic
        fi
        if [ -f /etc/sysconfig/yum-cron ]; then
            systemctl enable yum-cron
            systemctl start yum-cron
            echo "$(date -Iseconds) - yum-cron enabled" >> "$LOGFILE"
        elif [ -f /etc/dnf/automatic.conf ]; then
            systemctl enable dnf-automatic.timer
            systemctl start dnf-automatic.timer
            echo "$(date -Iseconds) - dnf-automatic enabled" >> "$LOGFILE"
        fi
    fi

    echo -e "${GREEN}Auto updates setup complete.${NC}"
    echo "$(date -Iseconds) - Phase7 complete" >> "$LOGFILE"
}

# --- Phase 8: Run Demo Container (Optional) ---
run_demo_container() {
    echo -e "${GREEN}[8/8] Optional: Running demo container...${NC}"
    echo "$(date -Iseconds) - Phase8: run_demo_container start" >> "$LOGFILE"

    read -r -p "$(echo -e "${YELLOW}Do you want to run a demo Nginx container using Docker Compose? (y/n, default n): ${NC}")" RUN_DEMO
    if ! [[ "$RUN_DEMO" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Skipping demo container.${NC}"
        echo "$(date -Iseconds) - Skipped demo container" >> "$LOGFILE"
        echo "$(date -Iseconds) - Phase8 complete" >> "$LOGFILE"
        return
    fi

    # Check for docker/ files
    if [ ! -f "docker/docker-compose.yml" ] || [ ! -f "docker/nginx.conf" ]; then
        echo -e "${RED}Demo files not found in docker/. Please add them as per project structure.${NC}"
        echo "$(date -Iseconds) - Demo files missing" >> "$LOGFILE"
        return
    fi

    # Setup directory for demo
    mkdir -p /opt/dockshield/docker
    cp docker/docker-compose.yml /opt/dockshield/docker/
    cp docker/nginx.conf /opt/dockshield/docker/

    # If SSL was set up, note for manual configuration
    if [ -n "$DOMAIN" ]; then
        echo -e "${YELLOW}SSL certificates available. Manually update nginx.conf to use them and restart the container.${NC}"
        echo "$(date -Iseconds) - SSL note for demo container" >> "$LOGFILE"
    fi

    # Run docker compose
    cd /opt/dockshield/docker
    docker compose up -d
    echo "$(date -Iseconds) - Demo Nginx container started" >> "$LOGFILE"

    echo -e "${GREEN}Demo container running. Access via http://your-server-ip (or https if configured).${NC}"
    echo "$(date -Iseconds) - Phase8 complete" >> "$LOGFILE"
}

# Execute in Order
secure_server
configure_firewall
harden_ssh
install_docker
setup_ssl
setup_backups
setup_auto_updates
run_demo_container

echo -e "${GREEN}=== DockShield Deployment Complete! ===${NC}"
echo "$(date -Iseconds) - Deployment complete" >> "$LOGFILE"
