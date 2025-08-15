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

# Ensure log file directory exists
mkdir -p "$(dirname "$LOGFILE")"
echo "$(date -Iseconds) - Starting DockShield" >> "$LOGFILE"

# --- Check Root Privileges ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo).${NC}"
    echo "$(date -Iseconds) - Error: Script not run as root" >> "$LOGFILE"
    exit 1
fi

# --- Detect OS ---
if [ -f /etc/debian_version ]; then
    OS="Debian"
    if grep -qi ubuntu /etc/os-release; then
        OS="Ubuntu"
    fi
elif [ -f /etc/redhat-release ]; then
    OS="RHEL"
else
    echo -e "${RED}Unsupported OS. DockShield supports Debian/Ubuntu & RHEL/CentOS.${NC}"
    echo "$(date -Iseconds) - Error: Unsupported OS" >> "$LOGFILE"
    exit 1
fi
echo -e "${YELLOW}Detected OS: $OS${NC}"
echo "$(date -Iseconds) - Detected OS: $OS" >> "$LOGFILE"

# --- Function to Wait for APT Lock ---
wait_for_apt() {
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        echo -e "${YELLOW}Checking for APT lock...${NC}"
        local timeout=300  # Wait up to 5 minutes
        local counter=0
        while [ -f /var/lib/dpkg/lock-frontend ] || [ -f /var/cache/apt/archives/lock ]; do
            if [ $counter -ge $timeout ]; then
                echo -e "${RED}Timeout waiting for APT lock. Another process may be using APT. Please try again later or resolve manually.${NC}"
                echo -e "${YELLOW}To check the process, run: ps aux | grep -E 'apt|dpkg'${NC}"
                echo "$(date -Iseconds) - Timeout waiting for APT lock" >> "$LOGFILE"
                return 1
            fi
            echo -e "${YELLOW}APT lock detected. Waiting...${NC}"
            sleep 5
            counter=$((counter + 5))
        done
        echo -e "${GREEN}APT lock cleared. Proceeding...${NC}"
        echo "$(date -Iseconds) - APT lock cleared" >> "$LOGFILE"
    fi
}

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
        echo -e "${YELLOW}No root authorized_keys found. To set up SSH for '$NEW_USER', follow these steps:${NC}"
        echo -e "${YELLOW}1. On your local machine, generate an SSH key (if not already done):${NC}"
        echo -e "${YELLOW}   ssh-keygen -t rsa -b 4096 -C \"your_email@example.com\"${NC}"
        echo -e "${YELLOW}2. Copy the public key to the server:${NC}"
        echo -e "${YELLOW}   ssh-copy-id $NEW_USER@your-server-ip${NC}"
        echo -e "${YELLOW}3. Test SSH login:${NC}"
        echo -e "${YELLOW}   ssh $NEW_USER@your-server-ip${NC}"
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

    # Restart SSH service
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        systemctl restart ssh || systemctl restart ssh.service || {
            echo -e "${RED}Failed to restart SSH service. Please check the service status with 'systemctl status ssh'.${NC}"
            echo "$(date -Iseconds) - Failed to restart SSH" >> "$LOGFILE"
            return 1
        }
    else
        systemctl restart sshd || systemctl restart sshd.service || {
            echo -e "${RED}Failed to restart SSH service. Please check the service status with 'systemctl status sshd'.${NC}"
            echo "$(date -Iseconds) - Failed to restart SSH" >> "$LOGFILE"
            return 1
        }
    fi

    echo -e "${GREEN}Root SSH login disabled and SSH configured.${NC}"
    echo "$(date -Iseconds) - Phase1 complete" >> "$LOGFILE"
}

# --- Phase 2: Firewall Configuration ---
configure_firewall() {
    echo -e "${GREEN}[2/8] Configuring firewall...${NC}"
    echo "$(date -Iseconds) - Phase2: firewall start" >> "$LOGFILE"

    SSH_PORT=22
    ALLOW_HTTP="n"
    ALLOW_HTTPS="n"

    read -r -p "$(echo -e "${YELLOW}Enter SSH port to allow (default 22): ${NC}")" INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" ]]; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi

    read -r -p "$(echo -e "${YELLOW}Allow HTTP (port 80)? (y/n, default n): ${NC}")" ALLOW_HTTP
    read -r -p "$(echo -e "${YELLOW}Allow HTTPS (port 443)? (y/n, default n): ${NC}")" ALLOW_HTTPS

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        if ! command -v ufw &>/dev/null; then
            echo -e "${YELLOW}ufw not found. Installing ufw...${NC}"
            wait_for_apt || return 1
            apt-get update && apt-get install -y ufw || {
                echo -e "${RED}Failed to install ufw. Please install manually with 'apt-get install ufw'.${NC}"
                echo "$(date -Iseconds) - Failed to install ufw" >> "$LOGFILE"
                return 1
            }
            echo "$(date -Iseconds) - ufw installed" >> "$LOGFILE"
        fi

        ufw default deny incoming
        ufw default allow outgoing
        ufw allow "$SSH_PORT"/tcp
        echo "$(date -Iseconds) - Allowed SSH port $SSH_PORT/tcp" >> "$LOGFILE"

        if [[ "$ALLOW_HTTP" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ufw allow 80/tcp
            echo "$(date -Iseconds) - Allowed HTTP (80)" >> "$LOGFILE"
        fi
        if [[ "$ALLOW_HTTPS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ufw allow 443/tcp
            echo "$(date -Iseconds) - Allowed HTTPS (443)" >> "$LOGFILE"
        fi

        if ufw status | grep -q "Status: active"; then
            echo -e "${YELLOW}ufw already active.${NC}"
            echo "$(date -Iseconds) - ufw already active" >> "$LOGFILE"
        else
            echo -e "${YELLOW}Enabling ufw...${NC}"
            ufw --force enable || {
                echo -e "${RED}Failed to enable ufw. Please check firewall settings.${NC}"
                echo "$(date -Iseconds) - Failed to enable ufw" >> "$LOGFILE"
                return 1
            }
            echo "$(date -Iseconds) - ufw enabled" >> "$LOGFILE"
        fi
    else
        if ! command -v firewall-cmd &>/dev/null; then
            echo -e "${YELLOW}firewalld not found. Installing firewalld...${NC}"
            if command -v yum &>/dev/null; then
                yum install -y firewalld || {
                    echo -e "${RED}Failed to install firewalld. Please install manually with 'yum install firewalld'.${NC}"
                    echo "$(date -Iseconds) - Failed to install firewalld" >> "$LOGFILE"
                    return 1
                }
            elif command -v dnf &>/dev/null; then
                dnf install -y firewalld || {
                    echo -e "${RED}Failed to install firewalld. Please install manually with 'dnf install firewalld'.${NC}"
                    echo "$(date -Iseconds) - Failed to install firewalld" >> "$LOGFILE"
                    return 1
                }
            fi
            systemctl enable --now firewalld
            echo "$(date -Iseconds) - firewalld installed and started" >> "$LOGFILE"
        fi

        firewall-cmd --permanent --remove-service=ftp 2>/dev/null || true
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

    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    echo "$(date -Iseconds) - Backed up sshd_config" >> "$LOGFILE"

    if [ -f "configs/sshd_config" ]; then
        cp configs/sshd_config "$SSHD_CONFIG"
        echo "$(date -Iseconds) - Copied custom sshd_config" >> "$LOGFILE"
    else
        if [ "$SSH_PORT" != "22" ]; then
            if grep -q "^Port" "$SSHD_CONFIG"; then
                sed -i "s/^Port.*/Port $SSH_PORT/" "$SSHD_CONFIG"
            else
                echo "Port $SSH_PORT" >> "$SSHD_CONFIG"
            fi
            echo "$(date -Iseconds) - Set SSH Port to $SSH_PORT" >> "$LOGFILE"
        fi

        if grep -q "^PubkeyAuthentication" "$SSHD_CONFIG"; then
            sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
        else
            echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
        fi

        if grep -q "^MaxAuthTries" "$SSHD_CONFIG"; then
            sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' "$SSHD_CONFIG"
        else
            echo "MaxAuthTries 4" >> "$SSHD_CONFIG"
        fi

        if grep -q "^LoginGraceTime" "$SSHD_CONFIG"; then
            sed -i 's/^LoginGraceTime.*/LoginGraceTime 30/' "$SSHD_CONFIG"
        else
            echo "LoginGraceTime 30" >> "$SSHD_CONFIG"
        fi

        if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
            sed -i "s/^AllowUsers.*/AllowUsers $NEW_USER/" "$SSHD_CONFIG"
        else
            echo "AllowUsers $NEW_USER" >> "$SSHD_CONFIG"
        fi
    fi

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        systemctl restart ssh || systemctl restart ssh.service || {
            echo -e "${RED}Failed to restart SSH service. Please check the service status with 'systemctl status ssh'.${NC}"
            echo "$(date -Iseconds) - Failed to restart SSH" >> "$LOGFILE"
            return 1
        }
    else
        systemctl restart sshd || systemctl restart sshd.service || {
            echo -e "${RED}Failed to restart SSH service. Please check the service status with 'systemctl status sshd'.${NC}"
            echo "$(date -Iseconds) - Failed to restart SSH" >> "$LOGFILE"
            return 1
        }
    fi
    echo "$(date -Iseconds) - SSH restarted" >> "$LOGFILE"

    echo -e "${YELLOW}Installing fail2ban for intrusion prevention...${NC}"
    # Remove invalid Docker repository if it exists
    if [ -f "/etc/apt/sources.list.d/docker.list" ]; then
        echo -e "${YELLOW}Removing invalid Docker repository...${NC}"
        rm /etc/apt/sources.list.d/docker.list
        echo "$(date -Iseconds) - Removed invalid Docker repository" >> "$LOGFILE"
    fi
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        wait_for_apt || return 1
        apt-get update && apt-get install -y fail2ban || {
            echo -e "${RED}Failed to install fail2ban. Please install manually with 'apt-get install fail2ban'.${NC}"
            echo "$(date -Iseconds) - Failed to install fail2ban" >> "$LOGFILE"
            return 1
        }
    else
        if command -v yum &>/dev/null; then
            yum install -y fail2ban || {
                echo -e "${RED}Failed to install fail2ban. Please install manually with 'yum install fail2ban'.${NC}"
                echo "$(date -Iseconds) - Failed to install fail2ban" >> "$LOGFILE"
                return 1
            }
        elif command -v dnf &>/dev/null; then
            dnf install -y fail2ban || {
                echo -e "${RED}Failed to install fail2ban. Please install manually with 'dnf install fail2ban'.${NC}"
                echo "$(date -Iseconds) - Failed to install fail2ban" >> "$LOGFILE"
                return 1
            }
        fi
    fi
    systemctl enable fail2ban || {
        echo -e "${RED}Failed to enable fail2ban. Please check the service status with 'systemctl status fail2ban'.${NC}"
        echo "$(date -Iseconds) - Failed to enable fail2ban" >> "$LOGFILE"
        return 1
    }
    systemctl start fail2ban || {
        echo -e "${RED}Failed to start fail2ban. Please check the service status with 'systemctl status fail2ban'.${NC}"
        echo "$(date -Iseconds) - Failed to start fail2ban" >> "$LOGFILE"
        return 1
    }
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

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        wait_for_apt || return 1
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release || {
            echo -e "${RED}Failed to install prerequisites for Docker. Please install manually with 'apt-get install apt-transport-https ca-certificates curl gnupg lsb-release'.${NC}"
            echo "$(date -Iseconds) - Failed to install Docker prerequisites" >> "$LOGFILE"
            return 1
        }
        curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        wait_for_apt || return 1
        apt-get update || {
            echo -e "${RED}Failed to update package lists for Docker. Please check the repository configuration.${NC}"
            echo "$(date -Iseconds) - Failed to update Docker repository" >> "$LOGFILE"
            return 1
        }
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || {
            echo -e "${RED}Failed to install Docker packages. Please install manually with 'apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin'.${NC}"
            echo "$(date -Iseconds) - Failed to install Docker packages" >> "$LOGFILE"
            return 1
        }
    else
        if command -v yum &>/dev/null; then
            yum install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || {
                echo -e "${RED}Failed to install Docker packages. Please install manually with 'yum install docker-ce docker-ce-cli containerd.io docker-compose-plugin'.${NC}"
                echo "$(date -Iseconds) - Failed to install Docker packages" >> "$LOGFILE"
                return 1
            }
        elif command -v dnf &>/dev/null; then
            dnf install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || {
                echo -e "${RED}Failed to install Docker packages. Please install manually with 'dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin'.${NC}"
                echo "$(date -Iseconds) - Failed to install Docker packages" >> "$LOGFILE"
                return 1
            }
        fi
    fi

    systemctl start docker || {
        echo -e "${RED}Failed to start Docker service. Please check the service status with 'systemctl status docker'.${NC}"
        echo "$(date -Iseconds) - Failed to start Docker" >> "$LOGFILE"
        return 1
    }
    systemctl enable docker || {
        echo -e "${RED}Failed to enable Docker service. Please check the service status with 'systemctl status docker'.${NC}"
        echo "$(date -Iseconds) - Failed to enable Docker" >> "$LOGFILE"
        return 1
    }
    usermod -aG docker "$NEW_USER" || {
        echo -e "${RED}Failed to add user to docker group. Please add manually with 'usermod -aG docker $NEW_USER'.${NC}"
        echo "$(date -Iseconds) - Failed to add user to docker group" >> "$LOGFILE"
        return 1
    }
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

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        wait_for_apt || return 1
        apt-get update && apt-get install -y certbot || {
            echo -e "${RED}Failed to install certbot. Please install manually with 'apt-get install certbot'.${NC}"
            echo "$(date -Iseconds) - Failed to install certbot" >> "$LOGFILE"
            return 1
        }
    else
        if command -v yum &>/dev/null; then
            yum install -y certbot || {
                echo -e "${RED}Failed to install certbot. Please install manually with 'yum install certbot'.${NC}"
                echo "$(date -Iseconds) - Failed to install certbot" >> "$LOGFILE"
                return 1
            }
        elif command -v dnf &>/dev/null; then
            dnf install -y certbot || {
                echo -e "${RED}Failed to install certbot. Please install manually with 'dnf install certbot'.${NC}"
                echo "$(date -Iseconds) - Failed to install certbot" >> "$LOGFILE"
                return 1
            }
        fi
    fi

    certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" || {
        echo -e "${RED}Failed to obtain SSL certificate. Ensure port 80 is open and the domain is correctly configured.${NC}"
        echo "$(date -Iseconds) - Failed to obtain SSL certificate for $DOMAIN" >> "$LOGFILE"
        return 1
    }
    echo "$(date -Iseconds) - SSL setup for $DOMAIN" >> "$LOGFILE"

    echo -e "${GREEN}SSL setup complete. Certificates are in /etc/letsencrypt/live/$DOMAIN${NC}"
    echo "$(date -Iseconds) - Phase5 complete" >> "$LOGFILE"
}

# --- Phase 6: Setup Backups ---
setup_backups() {
    echo -e "${GREEN}[6/8] Setting up daily backups...${NC}"
    echo "$(date -Iseconds) - Phase6: setup_backups start" >> "$LOGFILE"

    if ! command -v rsync &>/dev/null; then
        echo -e "${YELLOW}rsync not found. Installing rsync...${NC}"
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            wait_for_apt || return 1
            apt-get update && apt-get install -y rsync || {
                echo -e "${RED}Failed to install rsync. Please install manually with 'apt-get install rsync'.${NC}"
                echo "$(date -Iseconds) - Failed to install rsync" >> "$LOGFILE"
                return 1
            }
        else
            if command -v yum &>/dev/null; then
                yum install -y rsync || {
                    echo -e "${RED}Failed to install rsync. Please install manually with 'yum install rsync'.${NC}"
                    echo "$(date -Iseconds) - Failed to install rsync" >> "$LOGFILE"
                    return 1
                }
            elif command -v dnf &>/dev/null; then
                dnf install -y rsync || {
                    echo -e "${RED}Failed to install rsync. Please install manually with 'dnf install rsync'.${NC}"
                    echo "$(date -Iseconds) - Failed to install rsync" >> "$LOGFILE"
                    return 1
                }
            fi
        fi
        echo "$(date -Iseconds) - rsync installed" >> "$LOGFILE"
    fi

    mkdir -p /backups
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

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        wait_for_apt || return 1
        apt-get update && apt-get install -y unattended-upgrades || {
            echo -e "${RED}Failed to install unattended-upgrades. Please install manually with 'apt-get install unattended-upgrades'.${NC}"
            echo "$(date -Iseconds) - Failed to install unattended-upgrades" >> "$LOGFILE"
            return 1
        }
        dpkg-reconfigure -f noninteractive unattended-upgrades || {
            echo -e "${RED}Failed to configure unattended-upgrades. Please configure manually.${NC}"
            echo "$(date -Iseconds) - Failed to configure unattended-upgrades" >> "$LOGFILE"
            return 1
        }
        echo "$(date -Iseconds) - Unattended-upgrades installed and configured" >> "$LOGFILE"
    else
        if command -v yum &>/dev/null; then
            yum install -y yum-cron || {
                echo -e "${RED}Failed to install yum-cron. Please install manually with 'yum install yum-cron'.${NC}"
                echo "$(date -Iseconds) - Failed to install yum-cron" >> "$LOGFILE"
                return 1
            }
            systemctl enable yum-cron
            systemctl start yum-cron
            echo "$(date -Iseconds) - yum-cron enabled" >> "$LOGFILE"
        elif command -v dnf &>/dev/null; then
            dnf install -y dnf-automatic || {
                echo -e "${RED}Failed to install dnf-automatic. Please install manually with 'dnf install dnf-automatic'.${NC}"
                echo "$(date -Iseconds) - Failed to install dnf-automatic" >> "$LOGFILE"
                return 1
            }
            systemctl enable dnf-automatic.timer
            systemctl start dnf-automatic.timer
            echo "$(date -Iseconds) - dnf-automatic enabled" >> "$LOGFILE"
        fi
    fi

    echo -e "${GREEN}Auto updates setup complete.${NC}"
    echo "$(date -Iseconds) - Phase7 complete" >> "$LOGFILE"
}

# --- Phase 8: Run Demo Container ---
run_demo_container() {
    echo -e "${GREEN}[8/8] Optional: Running demo container...${NC}"
    echo "$(date -Iseconds) - Phase8: run_demo_container start" >> "$LOGFILE"

    if ! command -v docker &>/dev/null; then
        echo -e "${RED}Docker is not installed. Please run Phase 4 (Install Docker) first.${NC}"
        echo "$(date -Iseconds) - Docker not installed" >> "$LOGFILE"
        return 1
    fi

    read -r -p "$(echo -e "${YELLOW}Do you want to run a demo Nginx container using Docker Compose? (y/n, default n): ${NC}")" RUN_DEMO
    if ! [[ "$RUN_DEMO" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Skipping demo container.${NC}"
        echo "$(date -Iseconds) - Skipped demo container" >> "$LOGFILE"
        echo "$(date -Iseconds) - Phase8 complete" >> "$LOGFILE"
        return
    fi

    if [ ! -f "docker/docker-compose.yml" ] || [ ! -f "docker/nginx.conf" ]; then
        echo -e "${RED}Demo files not found in docker/. Please create docker/docker-compose.yml and docker/nginx.conf.${NC}"
        echo -e "${YELLOW}Example docker-compose.yml:${NC}"
        echo -e "version: '3'\nservices:\n  nginx:\n    image: nginx:latest\n    ports:\n      - \"80:80\"\n    volumes:\n      - ./nginx.conf:/etc/nginx/nginx.conf"
        echo -e "${YELLOW}Example nginx.conf:${NC}"
        echo -e "user nginx;\nworker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n    server {\n        listen 80;\n        server_name localhost;\n        location / {\n            root /usr/share/nginx/html;\n            index index.html;\n        }\n    }\n}"
        echo "$(date -Iseconds) - Demo files missing" >> "$LOGFILE"
        return 1
    fi

    mkdir -p /opt/dockshield/docker
    cp docker/docker-compose.yml /opt/dockshield/docker/
    cp docker/nginx.conf /opt/dockshield/docker/

    if [ -n "$DOMAIN" ]; then
        echo -e "${YELLOW}SSL certificates available. Manually update nginx.conf to use them and restart the container.${NC}"
        echo "$(date -Iseconds) - SSL note for demo container" >> "$LOGFILE"
    fi

    cd /opt/dockshield/docker
    docker compose up -d || {
        echo -e "${RED}Failed to start demo container. Please check Docker and the docker-compose.yml file.${NC}"
        echo "$(date -Iseconds) - Failed to start demo container" >> "$LOGFILE"
        return 1
    }
    echo "$(date -Iseconds) - Demo Nginx container started" >> "$LOGFILE"

    echo -e "${GREEN}Demo container running. Access via http://your-server-ip (or https if configured).${NC}"
    echo "$(date -Iseconds) - Phase8 complete" >> "$LOGFILE"
}

# --- Run All Phases ---
run_all_phases() {
    echo -e "${GREEN}Running all phases sequentially...${NC}"
    echo "$(date -Iseconds) - Running all phases" >> "$LOGFILE"

    secure_server || { echo -e "${RED}Phase 1 failed. Aborting.${NC}"; return 1; }
    configure_firewall || { echo -e "${RED}Phase 2 failed. Aborting.${NC}"; return 1; }
    harden_ssh || { echo -e "${RED}Phase 3 failed. Aborting.${NC}"; return 1; }
    install_docker || { echo -e "${RED}Phase 4 failed. Aborting.${NC}"; return 1; }
    setup_ssl || { echo -e "${RED}Phase 5 failed. Aborting.${NC}"; return 1; }
    setup_backups || { echo -e "${RED}Phase 6 failed. Aborting.${NC}"; return 1; }
    setup_auto_updates || { echo -e "${RED}Phase 7 failed. Aborting.${NC}"; return 1; }
    run_demo_container || { echo -e "${RED}Phase 8 failed. Aborting.${NC}"; return 1; }

    echo -e "${GREEN}All phases completed!${NC}"
    echo "$(date -Iseconds) - All phases completed" >> "$LOGFILE"
}

# --- Interactive CLI Menu ---
echo -e "${GREEN}=== Welcome to DockShield: Secure Server Deployment ===${NC}"
PS3="$(echo -e "${YELLOW}Select an option: ${NC}")"
options=(
    "Run All Phases"
    "1. Setup Secure User"
    "2. Configure Firewall"
    "3. Harden SSH"
    "4. Install Docker"
    "5. Setup SSL Certificates"
    "6. Setup Daily Backups"
    "7. Setup Auto Updates"
    "8. Run Demo Container"
    "Exit"
)

select opt in "${options[@]}"; do
    case $opt in
        "Run All Phases")
            run_all_phases
            break
            ;;
        "1. Setup Secure User")
            secure_server
            echo -e "${GREEN}Phase 1 completed. Returning to menu...${NC}"
            ;;
        "2. Configure Firewall")
            configure_firewall
            echo -e "${GREEN}Phase 2 completed. Returning to menu...${NC}"
            ;;
        "3. Harden SSH")
            harden_ssh
            echo -e "${GREEN}Phase 3 completed. Returning to menu...${NC}"
            ;;
        "4. Install Docker")
            install_docker
            echo -e "${GREEN}Phase 4 completed. Returning to menu...${NC}"
            ;;
        "5. Setup SSL Certificates")
            setup_ssl
            echo -e "${GREEN}Phase 5 completed. Returning to menu...${NC}"
            ;;
        "6. Setup Daily Backups")
            setup_backups
            echo -e "${GREEN}Phase 6 completed. Returning to menu...${NC}"
            ;;
        "7. Setup Auto Updates")
            setup_auto_updates
            echo -e "${GREEN}Phase 7 completed. Returning to menu...${NC}"
            ;;
        "8. Run Demo Container")
            run_demo_container
            echo -e "${GREEN}Phase 8 completed. Returning to menu...${NC}"
            ;;
        "Exit")
            echo -e "${GREEN}Exiting DockShield. Goodbye!${NC}"
            echo "$(date -Iseconds) - User exited script" >> "$LOGFILE"
            break
            ;;
        *)
            echo -e "${RED}Invalid option. Please select a number from 1 to ${#options[@]}.${NC}"
            ;;
    esac
done

echo -e "${GREEN}=== DockShield Deployment Complete! ===${NC}"
echo "$(date -Iseconds) - Deployment complete" >> "$LOGFILE"
