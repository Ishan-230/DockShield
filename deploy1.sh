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

# Display DockShield in big terminal UI
echo -e "${GREEN}"
cat << EOF


 ____             _     ____  _     _      _     _ 
|  _ \  ___   ___| | __/ ___|| |__ (_) ___| | __| |
| | | |/ _ \ / __| |/ /\___ \| '_ \| |/ _ \ |/ _` |
| |_| | (_) | (__|   <  ___) | | | | |  __/ | (_| |
|____/ \___/ \___|_|\_\|____/|_| |_|_|\___|_|\__,_|


EOF
echo -e "${NC}"

# Script Description
echo -e "${YELLOW}Welcome to DockShield!${NC}"
echo -e "This script automates the setup of a secure server:"
echo -e "- Creates a secure non-root user."
echo -e "- Disables root SSH login for security."
echo -e "- Configures a firewall to block unauthorized access."
echo -e "- Hardens SSH with limited attempts and fail2ban to ban attackers."
echo -e "- Installs Docker for running applications in containers."
echo -e "- Optionally sets up SSL certificates for secure web traffic."
echo -e "- Schedules daily backups using rsync."
echo -e "- Enables automatic security updates."
echo -e "- Optionally runs a demo Nginx container."
echo -e "Run phases individually or all at once via the menu."
echo -e "${YELLOW}Note: Set up SSH keys for secure access (prompted in Phase 1).${NC}"
echo -e ""

# --- Check Root Privileges ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo).${NC}"
    echo "$(date -Iseconds) - Error: Script not run as root" >> "$LOGFILE"
    exit 1
fi

# --- Detect OS ---
if [ -f /etc/debian_version ]; then
    OS="debian"
    if grep -qi ubuntu /etc/os-release; then
        OS="ubuntu"
    fi
elif [ -f /etc/redhat-release ]; then
    OS="rhel"
else
    echo -e "${RED}Unsupported OS. DockShield supports Debian/Ubuntu & RHEL/CentOS.${NC}"
    echo "$(date -Iseconds) - Error: Unsupported OS" >> "$LOGFILE"
    exit 1
fi
echo -e "${YELLOW}Detected OS: $OS${NC}"
echo "$(date -Iseconds) - Detected OS: $OS" >> "$LOGFILE"

# --- Function to Wait for APT Lock ---
wait_for_apt() {
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        echo -e "${YELLOW}Checking for APT lock...${NC}"
        local timeout=60  # Wait up to 1 minute
        local counter=0
        while [ -f /var/lib/dpkg/lock-frontend ] || [ -f /var/cache/apt/archives/lock ]; do
            if [ $counter -ge $timeout ]; then
                echo -e "${YELLOW}APT lock persists. Forcing lock release...${NC}"
                # Identify and kill processes holding APT locks
                ps aux | grep -E '[a]pt|[d]pkg' | grep -v grep | awk '{print $2}' | xargs -r kill -9
                # Remove lock files
                rm -f /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock
                # Repair dpkg database if needed
                dpkg --configure -a
                echo -e "${GREEN}APT locks forcibly cleared. Proceeding...${NC}"
                echo "$(date -Iseconds) - Forcibly cleared APT locks" >> "$LOGFILE"
                return 0
            fi
            echo -e "${YELLOW}APT lock detected. Waiting...${NC}"
            sleep 2
            counter=$((counter + 2))
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

    # Option to setup SSH key through the script
    read -r -p "$(echo -e "${YELLOW}Do you want to set up SSH keys for '$NEW_USER'? (y/n, default n): ${NC}")" SETUP_KEYS
    if [[ "$SETUP_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Paste your public SSH key below (e.g., ssh-rsa AAA...):${NC}"
        read -r PUBLIC_KEY
        if [ -n "$PUBLIC_KEY" ]; then
            mkdir -p /home/$NEW_USER/.ssh
            echo "$PUBLIC_KEY" >> /home/$NEW_USER/.ssh/authorized_keys
            chmod 600 /home/$NEW_USER/.ssh/authorized_keys
            chmod 700 /home/$NEW_USER/.ssh
            chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
            echo -e "${GREEN}SSH key added to '$NEW_USER'.${NC}"
            echo "$(date -Iseconds) - SSH key added to $NEW_USER" >> "$LOGFILE"
        else
            echo -e "${RED}No public key provided. Skipping SSH key setup.${NC}"
            echo "$(date -Iseconds) - No public key provided for SSH setup" >> "$LOGFILE"
        fi
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
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)"
    echo "$(date -Iseconds) - Backed up sshd_config" >> "$LOGFILE"

    if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    else
        echo "PermitRootLogin no" >> "$SSHD_CONFIG"
    fi

    # Ensure PasswordAuthentication is enabled if no keys are present
    if [ ! -f "/home/$NEW_USER/.ssh/authorized_keys" ] && [ ! -f "/root/.ssh/authorized_keys" ]; then
        if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
        else
            echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
        fi
        echo -e "${YELLOW}No SSH keys found. Enabling password authentication to prevent lockout.${NC}"
        echo "$(date -Iseconds) - Enabled PasswordAuthentication (no keys found)" >> "$LOGFILE"
    else
        # Optionally enforce key-based authentication
        read -r -p "$(echo -e "${YELLOW}Do you want to enforce key-based SSH authentication only? (y/n): ${NC}")" ENFORCE_KEYS
        if [[ "$ENFORCE_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
                sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
            else
                echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
            fi
            echo "$(date -Iseconds) - Enforced key-based SSH authentication" >> "$LOGFILE"
        fi
    fi

    # Validate SSH configuration
    sshd -t
    if [ $? -ne 0 ]; then
        echo -e "${RED}SSH configuration is invalid. Restoring backup and aborting.${NC}"
        cp "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)" "$SSHD_CONFIG"
        echo "$(date -Iseconds) - Restored sshd_config due to invalid configuration" >> "$LOGFILE"
        return 1
    fi

    # Restart SSH service
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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
    HTTP_PORT=80
    HTTPS_PORT=443
    ALLOW_HTTP="n"
    ALLOW_HTTPS="n"

    read -r -p "$(echo -e "${YELLOW}Enter SSH port to allow (default 22) - please write the port number: ${NC}")" INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" ]]; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi

    read -r -p "$(echo -e "${YELLOW}Allow HTTP (port 80)? (y/n, default n) - HTTP is for unencrypted web traffic; keep open if hosting a website without SSL: ${NC}")" ALLOW_HTTP
    read -r -p "$(echo -e "${YELLOW}Allow HTTPS (port 443)? (y/n, default n) - HTTPS is for encrypted web traffic; keep open for secure websites with SSL: ${NC}")" ALLOW_HTTPS

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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
            ufw allow "$HTTP_PORT"/tcp
            echo "$(date -Iseconds) - Allowed HTTP ($HTTP_PORT)" >> "$LOGFILE"
        fi
        if [[ "$ALLOW_HTTPS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ufw allow "$HTTPS_PORT"/tcp
            echo "$(date -Iseconds) - Allowed HTTPS ($HTTPS_PORT)" >> "$LOGFILE"
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
            firewall-cmd --permanent --add-port=${HTTP_PORT}/tcp
            echo "$(date -Iseconds) - Allowed HTTP ($HTTP_PORT) (firewalld)" >> "$LOGFILE"
        fi
        if [[ "$ALLOW_HTTPS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            firewall-cmd --permanent --add-port=${HTTPS_PORT}/tcp
            echo "$(date -Iseconds) - Allowed HTTPS ($HTTPS_PORT) (firewalld)" >> "$LOGFILE"
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

    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)"
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

    # Validate SSH configuration
    sshd -t
    if [ $? -ne 0 ]; then
        echo -e "${RED}SSH configuration is invalid. Restoring backup and aborting.${NC}"
        cp "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)" "$SSHD_CONFIG"
        echo "$(date -Iseconds) - Restored sshd_config due to invalid configuration" >> "$LOGFILE"
        return 1
    fi

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        wait_for_apt || return 1
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release || {
            echo -e "${RED}Failed to install prerequisites for Docker. Please install manually with 'apt-get install apt-transport-https ca-certificates curl gnupg lsb-release'.${NC}"
            echo "$(date -Iseconds) - Failed to install Docker prerequisites" >> "$LOGFILE"
            return 1
        }
        # Remove existing Docker GPG key if it exists
        rm -f /usr/share/keyrings/docker-archive-keyring.gpg
        curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg || {
            echo -e "${RED}Failed to download Docker GPG key. Please check network connectivity or try again later.${NC}"
            echo "$(date -Iseconds) - Failed to download Docker GPG key" >> "$LOGFILE"
            return 1
        }
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        wait_for_apt || return 1
        apt-get update || {
            echo -e "${RED}Failed to update package lists for Docker. Please check the repository configuration or network connectivity.${NC}"
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

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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
        if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
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
        echo -e "${RED}Demo files not found in docker/. Please add them as per project structure.${NC}"
        echo "$(date -Iseconds) - Demo files missing" >> "$LOGFILE"
        return 1
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

# --- Run All Phases ---
run_all_phases() {
    echo -e "${GREEN}Running all phases sequentially...${NC}"
    echo "$(date -Iseconds) - Running all phases" >> "$LOGFILE"

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
            ;;
        "2. Configure Firewall")
            configure_firewall
            ;;
        "3. Harden SSH")
            harden_ssh
            ;;
        "4. Install Docker")
            install_docker
            ;;
        "5. Setup SSL Certificates")
            setup_ssl
            ;;
        "6. Setup Daily Backups")
            setup_backups
            ;;
        "7. Setup Auto Updates")
            setup_auto_updates
            ;;
        "8. Run Demo Container")
            run_demo_container
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
