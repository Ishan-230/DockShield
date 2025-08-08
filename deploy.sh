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

    # Create new user if it doesn't exist
    if id "$NEW_USER" &>/dev/null; then
        echo -e "${YELLOW}User '$NEW_USER' already exists. Skipping creation.${NC}"
    else
        adduser --gecos "" "$NEW_USER"
        echo -e "${YELLOW}Set a strong password for $NEW_USER:${NC}"
        passwd "$NEW_USER"
    fi

    # Add to sudoers
    usermod -aG sudo "$NEW_USER"

    # Disable root SSH login
    echo -e "${YELLOW}Disabling root SSH login...${NC}"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

    # Optional: Enforce key-based authentication
    echo -e "${YELLOW}Do you want to enforce key-based SSH authentication only? (y/n): ${NC}"
    read -r ENFORCE_KEYS
    if [[ "$ENFORCE_KEYS" == "y" ]]; then
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    fi

    # Restart SSH service
    echo -e "${YELLOW}Restarting SSH service...${NC}"
    if [ "$OS" == "Debian" ]; then
        systemctl restart ssh
    else
        systemctl restart sshd
    fi

    echo -e "${GREEN}Secure user setup complete.${NC}"
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
