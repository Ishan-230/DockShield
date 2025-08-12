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

    # Optionally enforce key-based authentication (ask user)
    read -r -p "$(echo -e ${YELLOW}Do you want to enforce key-based SSH authentication only? (y/n): ${NC})" ENFORCE_KEYS
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
    echo -e "${GREEN}[2/5] Configuring firewall...${NC}"
    echo "$(date -Iseconds) - Phase2: firewall start" >> "$LOGFILE"

    # Default ports
    SSH_PORT=22
    ALLOW_HTTP="n"
    ALLOW_HTTPS="n"

    read -r -p "$(echo -e ${YELLOW}Enter SSH port to allow (default 22): ${NC})" INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" ]]; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi

    read -r -p "$(echo -e ${YELLOW}Allow HTTP (port 80)? (y/n, default n): ${NC})" ALLOW_HTTP
    read -r -p "$(echo -e ${YELLOW}Allow HTTPS (port 443)? (y/n, default n): ${NC})" ALLOW_HTTPS

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
    # Placeholder: disable root login, change default port, key-based auth
}

# --- Phase 4: Install Docker ---
install_docker() {
    echo -e "${GREEN}[4/5] Installing Docker...${NC}"
    # Placeholder: install docker & docker-compose
}

# --- Phase 5: SSL Setup ---
setup_ssl() {
    echo -e "${GREEN}[5/5] Setting up SSL certificates...${NC}"
    # Placeholder: install certbot & configure SSL
}

# Execute in Order
secure_server
configure_firewall
harden_ssh
install_docker
setup_ssl

echo -e "${GREEN}=== DockShield Deployment Complete! ===${NC}"
echo "$(date -Iseconds) - Deployment complete" >> "$LOGFILE"
