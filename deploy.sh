#!/bin/bash

# ============================
# DockShield - Automated Secure Server Deployment with Docker Integration
# ============================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== DockShield: Starting Automated Secure Server Deployment ===${NC}"

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

# --- Phase 1: Secure Server Setup ---
secure_server() {
    echo -e "${GREEN}[1/5] Setting up secure user...${NC}"

    NEW_USER="dockshield"

    # Create user if not exists
    if id "$NEW_USER" &>/dev/null; then
        echo -e "${YELLOW}User '$NEW_USER' already exists. Skipping creation...${NC}"
    else
        adduser "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        echo -e "${GREEN}User '$NEW_USER' created and added to sudo group.${NC}"
    fi

    # Setup SSH keys for new user
    if [ ! -d "/home/$NEW_USER/.ssh" ]; then
        mkdir -p /home/$NEW_USER/.ssh
        chmod 700 /home/$NEW_USER/.ssh
    fi

    if [ -f "/root/.ssh/authorized_keys" ]; then
        cp /root/.ssh/authorized_keys /home/$NEW_USER/.ssh/
        chmod 600 /home/$NEW_USER/.ssh/authorized_keys
        chown -R "$NEW_USER":"$NEW_USER" /home/$NEW_USER/.ssh
        echo -e "${GREEN}SSH key copied to '$NEW_USER'.${NC}"
    else
        echo -e "${YELLOW}No root authorized_keys found. You'll need to set up SSH manually for '$NEW_USER'.${NC}"
    fi

    # Disable root SSH login
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    else
        echo "PermitRootLogin no" >> "$SSHD_CONFIG"
    fi

    systemctl restart sshd
    echo -e "${GREEN}Root SSH login disabled.${NC}"
}

# --- Phase 2: Firewall Configuration ---
configure_firewall() {
    echo -e "${GREEN}[2/5] Configuring firewall...${NC}"
    # Placeholder: allow only essential ports, enable UFW/firewalld
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
