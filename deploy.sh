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
    echo -e "${GREEN}[1/5] Setting up secure user...${NC}"
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

    # Optionally enforce key-based authentication
    echo -e "${YELLOW}Do you want to enforce key-based SSH authentication only? (y/n): ${NC}"
    read -r ENFORCE_KEYS
    if [[ "$ENFORCE_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
        else
            echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
        fi
        echo "$(date -Iseconds) - Enforced key-based SSH authentication" >> "$LOGFILE"
    fi

    # Restart SSH service
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
    echo -e "${GREEN}[2/5] Configuring firewall...${NC}"
    echo "$(date -Iseconds) - Phase2: firewall start" >> "$LOGFILE"

    # Default ports
    SSH_PORT=22
    ALLOW_HTTP="n"
    ALLOW_HTTPS="n"

    echo -e "${YELLOW}Enter SSH port to allow (default 22): ${NC}"
    read -r INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" ]]; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi

    echo -e "${YELLOW}Allow HTTP (port 80)? (y/n, default n): ${NC}"
    read -r ALLOW_HTTP
    echo -e "${YELLOW}Allow HTTPS (port 443)? (y/n, default n): ${NC}"
    read -r ALLOW_HTTPS

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
    echo -e "${GREEN}[3/5] Hardening SSH configuration...${NC}"
    echo "$(date -Iseconds) - Phase3: SSH hardening start" >> "$LOGFILE"

    SSHD_CONFIG="/etc/ssh/sshd_config"

    # Backup original SSH config
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    echo "$(date -Iseconds) - Backed up $SSHD_CONFIG to ${SSHD_CONFIG}.bak" >> "$LOGFILE"

    # Apply hardened settings
    cat << EOF > "$SSHD_CONFIG"
# Hardened SSH configuration by DockShield
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers dockshield
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 0
UseDNS no
GSSAPIAuthentication no
EOF

    # Validate SSH config
    if sshd -t; then
        echo -e "${GREEN}SSH configuration validated successfully.${NC}"
        echo "$(date -Iseconds) - SSH configuration validated" >> "$LOGFILE"
    else
        echo -e "${RED}SSH configuration test failed. Restoring backup...${NC}"
        cp "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
        echo "$(date -Iseconds) - SSH configuration test failed, restored backup" >> "$LOGFILE"
        exit 1
    fi

    # Restart SSH service
    if [ "$OS" == "Debian" ]; then
        systemctl restart ssh || systemctl restart ssh.service
    else
        systemctl restart sshd || systemctl restart sshd.service
    fi

    echo -e "${GREEN}SSH hardening complete.${NC}"
    echo "$(date -Iseconds) - Phase3 complete" >> "$LOGFILE"
}

# --- Phase 4: Install Docker ---
install_docker() {
    echo -e "${GREEN}[4/5] Installing Docker...${NC}"
    echo "$(date -Iseconds) - Phase4: Docker installation start" >> "$LOGFILE"

    if command -v docker &>/dev/null; then
        echo -e "${YELLOW}Docker already installed. Skipping...${NC}"
        echo "$(date -Iseconds) - Docker already installed" >> "$LOGFILE"
    else
        if [ "$OS" == "Debian" ]; then
            apt-get update
            apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
            curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update
            apt-get install -y docker-ce docker-ce-cli containerd.io
            echo "$(date -Iseconds) - Docker installed on Debian" >> "$LOGFILE"
        else
            if command -v yum &>/dev/null; then
                yum install -y yum-utils
                yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                yum install -y docker-ce docker-ce-cli containerd.io
            elif command -v dnf &>/dev/null; then
                dnf install -y dnf-plugins-core
                dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                dnf install -y docker-ce docker-ce-cli containerd.io
            fi
            echo "$(date -Iseconds) - Docker installed on RHEL/CentOS" >> "$LOGFILE"
        fi

        systemctl enable docker
        systemctl start docker
        echo "$(date -Iseconds) - Docker service enabled and started" >> "$LOGFILE"
    fi

    # Install Docker Compose
    if command -v docker-compose &>/dev/null; then
        echo -e "${YELLOW}Docker Compose already installed. Skipping...${NC}"
        echo "$(date -Iseconds) - Docker Compose already installed" >> "$LOGFILE"
    else
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        echo "$(date -Iseconds) - Docker Compose installed" >> "$LOGFILE"
    fi

    # Add dockshield user to docker group
    usermod -aG docker dockshield
    echo "$(date -Iseconds) - Added dockshield user to docker group" >> "$LOGFILE"

    # Run a demo container (optional)
    echo -e "${YELLOW}Run a demo Nginx container? (y/n): ${NC}"
    read -r RUN_DEMO
    if [[ "$RUN_DEMO" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        docker run -d -p 80:80 nginx
        echo -e "${GREEN}Demo Nginx container running on port 80.${NC}"
        echo "$(date -Iseconds) - Demo Nginx container started" >> "$LOGFILE"
    fi

    echo -e "${GREEN}Docker installation complete.${NC}"
    echo "$(date -Iseconds) - Phase4 complete" >> "$LOGFILE"
}

# --- Phase 5: SSL Setup ---
setup_ssl() {
    echo -e "${GREEN}[5/5] Setting up SSL certificates...${NC}"
    echo "$(date -Iseconds) - Phase5: SSL setup start" >> "$LOGFILE"

    echo -e "${YELLOW}Do you want to set up SSL with Let's Encrypt? (y/n): ${NC}"
    read -r SETUP_LE
    if [[ "$SETUP_LE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Enter your domain name (e.g., example.com): ${NC}"
        read -r DOMAIN
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}No domain provided. Skipping SSL setup.${NC}"
            echo "$(date -Iseconds) - No domain provided for SSL" >> "$LOGFILE"
            return
        fi

        echo -e "${YELLOW}Enter your email for Let's Encrypt notifications: ${NC}"
        read -r EMAIL
        if [ -z "$EMAIL" ]; then
            echo -e "${RED}No email provided. Skipping SSL setup.${NC}"
            echo "$(date -Iseconds) - No email provided for SSL" >> "$LOGFILE"
            return
        fi

        if [ "$OS" == "Debian" ]; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
            echo "$(date -Iseconds) - Certbot installed on Debian" >> "$LOGFILE"
        else
            if command -v yum &>/dev/null; then
                yum install -y certbot python3-certbot-nginx
            elif command -v dnf &>/dev/null; then
                dnf install -y certbot python3-certbot-nginx
            fi
            echo "$(date -Iseconds) - Certbot installed on RHEL/CentOS" >> "$LOGFILE"
        fi

        # Run Certbot
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}SSL certificate installed for $DOMAIN.${NC}"
            echo "$(date -Iseconds) - SSL certificate installed for $DOMAIN" >> "$LOGFILE"
        else
            echo -e "${RED}Failed to install SSL certificate. Please check Certbot logs.${NC}"
            echo "$(date -Iseconds) - SSL certificate installation failed" >> "$LOGFILE"
        fi
    else
        echo -e "${YELLOW}Skipping SSL setup.${NC}"
        echo "$(date -Iseconds) - SSL setup skipped" >> "$LOGFILE"
    fi

    echo -e "${GREEN}SSL setup complete.${NC}"
    echo "$(date -Iseconds) - Phase5 complete" >> "$LOGFILE"
}

# Execute in Order
secure_server
configure_firewall
harden_ssh
install_docker
setup_ssl

echo -e "${GREEN}=== DockShield Deployment Complete! ===${NC}"
echo "$(date -Iseconds) - Deployment complete" >> "$LOGFILE"
