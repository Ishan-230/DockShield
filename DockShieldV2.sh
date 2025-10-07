#!/bin/bash

# ============================
# DockShield v2 - Automated Secure Server Deployment with Docker Integration
# ============================

# --- Global Configuration ---
NEW_USER="dockshield"
SSH_PORT=22

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOGFILE="/var/log/dockshield_deploy.log"

# Ensure log file directory exists
mkdir -p "$(dirname "$LOGFILE")"
echo "$(date -Iseconds) - Starting DockShield v2" >> "$LOGFILE"

# Display DockShield in big terminal UI
echo -e "${GREEN}"
cat << EOF


 ____              _      ____  _     _     _     _
|  _ \  ___     ___| | __ / ___|| |__ (_)___| | __| |
| | | |/ _ \ / __| |/ / \___ \| '_ \| |/ _ \ |/ _` |
| |_| | (_) | (__|   <   ___) | | | | |  __/ | (_| |
|____/ \___/ \___|_|\_\|____/|_| |_|_|\___|_|\__,_|


EOF
echo -e "${NC}"

# Script Description
echo -e "${YELLOW}Welcome to DockShield!${NC}"
echo -e "This script automates the setup of a secure server:"
echo -e "- Creates a secure non-root user ('$NEW_USER')."
echo -e "- Disables root SSH login and hardens SSH."
echo -e "- Configures a firewall (ufw/firewalld)."
echo -e "- Installs Docker for running applications in containers."
echo -e "- Optionally sets up SSL certificates with Let's Encrypt."
echo -e "- Schedules daily backups with a 7-day rotation."
echo -e "- Enables automatic security updates."
echo -e "- Optionally deploys a sample container (Nginx or Portainer)."
echo -e "Run phases individually or all at once via the menu."
echo -e "${YELLOW}Note: You will be prompted to set up SSH keys for secure access.${NC}"
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
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
            if [ $counter -ge $timeout ]; then
                echo -e "${YELLOW}APT lock persists. Forcing lock release...${NC}"
                # Identify and kill processes holding APT locks
                lsof /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock | awk 'NR>1 {print $2}' | xargs -r kill -9
                # Remove lock files
                rm -f /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock
                # Repair dpkg database if needed
                dpkg --configure -a
                echo -e "${GREEN}APT locks forcibly cleared. Proceeding...${NC}"
                echo "$(date -Iseconds) - Forcibly cleared APT locks" >> "$LOGFILE"
                return 0
            fi
            echo -e "${YELLOW}APT lock detected. Waiting... ($((counter/2))/30)${NC}"
            sleep 2
            counter=$((counter + 2))
        done
        echo -e "${GREEN}APT is available. Proceeding...${NC}"
    fi
}

# --- Phase 1: Secure Server Setup ---
secure_server() {
    echo -e "${GREEN}[1/8] Setting up secure user...${NC}"
    echo "$(date -Iseconds) - Phase1: secure_user start" >> "$LOGFILE"

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
    read -r -p "${YELLOW}Do you want to set up an SSH key for '$NEW_USER' now? (y/n): ${NC}" SETUP_KEYS
    if [[ "$SETUP_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Paste your public SSH key below (e.g., ssh-rsa AAA...):${NC}"
        read -r PUBLIC_KEY
        if [ -n "$PUBLIC_KEY" ]; then
            mkdir -p /home/$NEW_USER/.ssh
            echo "$PUBLIC_KEY" >> /home/$NEW_USER/.ssh/authorized_keys
            chmod 600 /home/$NEW_USER/.ssh/authorized_keys
            chmod 700 /home/$NEW_USER/.ssh
            chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
            echo -e "${GREEN}SSH key added for '$NEW_USER'.${NC}"
            echo "$(date -Iseconds) - SSH key added to $NEW_USER" >> "$LOGFILE"
        else
            echo -e "${RED}No public key provided. Skipping SSH key setup.${NC}"
            echo "$(date -Iseconds) - No public key provided for SSH setup" >> "$LOGFILE"
        fi
    else
        echo -e "${YELLOW}Skipping direct key setup. You can add a key later using 'ssh-copy-id $NEW_USER@your-server-ip'.${NC}"
    fi

    SSHD_CONFIG="/etc/ssh/sshd_config"
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)"

    # Disable root SSH login
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    if ! grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
        echo "PermitRootLogin no" >> "$SSHD_CONFIG"
    fi
    
    # Prevent lockout by checking for keys
    if [ ! -f "/home/$NEW_USER/.ssh/authorized_keys" ] && [ ! -f "/root/.ssh/authorized_keys" ]; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
        if ! grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
            echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
        fi
        echo -e "${YELLOW}WARNING: No SSH keys found. PasswordAuthentication has been enabled to prevent lockout.${NC}"
        echo "$(date -Iseconds) - Enabled PasswordAuthentication (no keys found)" >> "$LOGFILE"
    else
        read -r -p "${YELLOW}SSH key found. Enforce key-only authentication? (disables passwords) (y/n): ${NC}" ENFORCE_KEYS
        if [[ "$ENFORCE_KEYS" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
            if ! grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
                echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
            fi
            echo -e "${GREEN}PasswordAuthentication disabled. Key-based auth is now enforced.${NC}"
            echo "$(date -Iseconds) - Enforced key-based SSH authentication" >> "$LOGFILE"
        fi
    fi

    sshd -t || { echo -e "${RED}sshd_config validation failed. Aborting changes.${NC}"; mv "${SSHD_CONFIG}.bak_$(date +%Y%m%d_%H%M%S)" "$SSHD_CONFIG"; return 1; }

    systemctl restart sshd || systemctl restart ssh
    echo -e "${GREEN}Root SSH login disabled and SSH service restarted.${NC}"
    echo "$(date -Iseconds) - Phase1 complete" >> "$LOGFILE"
}

# --- Phase 2: Firewall Configuration ---
configure_firewall() {
    echo -e "${GREEN}[2/8] Configuring firewall...${NC}"
    echo "$(date -Iseconds) - Phase2: firewall start" >> "$LOGFILE"

    read -r -p "${YELLOW}Enter SSH port to allow (default 22): ${NC}" INPUT_SSH_PORT
    if [[ -n "$INPUT_SSH_PORT" && "$INPUT_SSH_PORT" -eq "$INPUT_SSH_PORT" ]] 2>/dev/null; then
        SSH_PORT="$INPUT_SSH_PORT"
    fi
    echo -e "${YELLOW}Firewall will be configured for SSH on port $SSH_PORT.${NC}"

    read -r -p "${YELLOW}Allow HTTP (port 80)? (Required for websites without SSL) (y/n): ${NC}" ALLOW_HTTP
    read -r -p "${YELLOW}Allow HTTPS (port 443)? (Required for secure websites with SSL) (y/n): ${NC}" ALLOW_HTTPS

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        command -v ufw &>/dev/null || { echo "Installing ufw..."; wait_for_apt; apt-get update && apt-get install -y ufw; }
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow "$SSH_PORT"/tcp
        [[ "$ALLOW_HTTP" =~ ^[yY]$ ]] && ufw allow 80/tcp
        [[ "$ALLOW_HTTPS" =~ ^[yY]$ ]] && ufw allow 443/tcp
        ufw --force enable
    else # RHEL-based
        command -v firewall-cmd &>/dev/null || { echo "Installing firewalld..."; yum install -y firewalld || dnf install -y firewalld; systemctl enable --now firewalld; }
        firewall-cmd --permanent --remove-service=ftp --quiet 2>/dev/null || true
        firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
        [[ "$ALLOW_HTTP" =~ ^[yY]$ ]] && firewall-cmd --permanent --add-service=http
        [[ "$ALLOW_HTTPS" =~ ^[yY]$ ]] && firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi

    echo -e "${GREEN}Firewall configuration complete.${NC}"
    echo "$(date -Iseconds) - Phase2 complete" >> "$LOGFILE"
}

# --- Phase 3: SSH Hardening ---
harden_ssh() {
    echo -e "${GREEN}[3/8] Hardening SSH configuration...${NC}"
    echo "$(date -Iseconds) - Phase3: harden_ssh start" >> "$LOGFILE"
    
    SSHD_CONFIG="/etc/ssh/sshd_config"
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_hardening_$(date +%Y%m%d_%H%M%S)"
    
    # Apply hardening settings
    sed -i "s/^#?Port .*/Port $SSH_PORT/" "$SSHD_CONFIG"
    if ! grep -q "^Port" "$SSHD_CONFIG"; then echo "Port $SSH_PORT" >> "$SSHD_CONFIG"; fi
    
    sed -i "s/^#?MaxAuthTries .*/MaxAuthTries 3/" "$SSHD_CONFIG"
    if ! grep -q "^MaxAuthTries" "$SSHD_CONFIG"; then echo "MaxAuthTries 3" >> "$SSHD_CONFIG"; fi

    sed -i "s/^#?LoginGraceTime .*/LoginGraceTime 30/" "$SSHD_CONFIG"
    if ! grep -q "^LoginGraceTime" "$SSHD_CONFIG"; then echo "LoginGraceTime 30" >> "$SSHD_CONFIG"; fi
    
    sed -i "s/^#?AllowUsers .*/AllowUsers $NEW_USER/" "$SSHD_CONFIG"
    if ! grep -q "^AllowUsers" "$SSHD_CONFIG"; then echo "AllowUsers $NEW_USER" >> "$SSHD_CONFIG"; fi
    
    sshd -t || { echo -e "${RED}sshd_config validation failed. Restoring backup.${NC}"; mv "${SSHD_CONFIG}.bak_hardening_$(date +%Y%m%d_%H%M%S)" "$SSHD_CONFIG"; return 1; }
    systemctl restart sshd || systemctl restart ssh
    echo "$(date -Iseconds) - SSH hardened and port set to $SSH_PORT" >> "$LOGFILE"

    echo -e "${YELLOW}Installing fail2ban for intrusion prevention...${NC}"
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        wait_for_apt; apt-get update && apt-get install -y fail2ban
    else
        yum install -y fail2ban || dnf install -y fail2ban
    fi
    systemctl enable --now fail2ban
    
    echo -e "${GREEN}SSH hardening complete. Remember to connect using port $SSH_PORT from now on!${NC}"
    echo "$(date -Iseconds) - Phase3 complete" >> "$LOGFILE"
}

# --- Phase 4: Install Docker ---
install_docker() {
    echo -e "${GREEN}[4/8] Installing Docker...${NC}"
    echo "$(date -Iseconds) - Phase4: install_docker start" >> "$LOGFILE"

    if command -v docker &>/dev/null; then
        echo -e "${YELLOW}Docker already installed. Skipping...${NC}"
        usermod -aG docker "$NEW_USER" # Ensure user is in group
        return
    fi

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        wait_for_apt
        apt-get update
        apt-get install -y ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        wait_for_apt
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else # RHEL-based
        yum install -y yum-utils || dnf install -y dnf-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi

    systemctl enable --now docker
    usermod -aG docker "$NEW_USER"
    echo -e "${GREEN}Docker installation complete. User '$NEW_USER' added to the 'docker' group.${NC}"
    echo "$(date -Iseconds) - Phase4 complete" >> "$LOGFILE"
}

# --- Phase 5: SSL Setup ---
setup_ssl() {
    echo -e "${GREEN}[5/8] Setting up SSL certificates...${NC}"
    echo "$(date -Iseconds) - Phase5: setup_ssl start" >> "$LOGFILE"

    read -r -p "${YELLOW}Do you want to set up SSL with Let's Encrypt? (y/n): ${NC}" SETUP_SSL
    if ! [[ "$SETUP_SSL" =~ ^[yY]$ ]]; then
        echo -e "${YELLOW}Skipping SSL setup.${NC}"
        return
    fi
    
    echo -e "${YELLOW}NOTE: For certbot to succeed, your domain must point to this server's IP, and port 80 must be open and not in use.${NC}"
    read -r -p "${YELLOW}Enter your domain name: ${NC}" DOMAIN
    read -r -p "${YELLOW}Enter your email for Let's Encrypt renewal notices: ${NC}" EMAIL

    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        echo -e "${RED}Domain and email are required. Skipping SSL setup.${NC}"
        return 1
    fi

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        wait_for_apt; apt-get update && apt-get install -y certbot
    else
        yum install -y certbot || dnf install -y certbot
    fi

    certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" || {
        echo -e "${RED}Failed to obtain SSL certificate. Please check your DNS settings and ensure port 80 is free.${NC}"
        return 1
    }
    echo -e "${GREEN}SSL setup complete. Certificates are in /etc/letsencrypt/live/$DOMAIN${NC}"
    echo "$(date -Iseconds) - Phase5 complete" >> "$LOGFILE"
}

# --- Phase 6: Setup Backups ---
setup_backups() {
    echo -e "${GREEN}[6/8] Setting up daily backups...${NC}"
    echo "$(date -Iseconds) - Phase6: setup_backups start" >> "$LOGFILE"

    command -v rsync &>/dev/null || {
        echo "Installing rsync...";
        if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
            wait_for_apt; apt-get update && apt-get install -y rsync;
        else
            yum install -y rsync || dnf install -y rsync;
        fi
    }

    mkdir -p /backups
    CRON_FILE="/etc/cron.d/dockshield-backup"
    
    # Backup job: creates a dated backup of /home and /etc
    BACKUP_JOB="0 2 * * * root rsync -a --delete /home/ /backups/home_$(date +\%Y\%m\%d) && rsync -a --delete /etc/ /backups/etc_$(date +\%Y\%m\%d)"
    # Cleanup job: removes backup directories older than 7 days
    CLEANUP_JOB="0 3 * * * root find /backups/ -type d -name '*_*' -mtime +7 -exec rm -rf {} \;"

    echo "$BACKUP_JOB" > "$CRON_FILE"
    echo "$CLEANUP_JOB" >> "$CRON_FILE"
    
    echo -e "${GREEN}Backups configured. /home and /etc will be backed up daily to /backups.${NC}"
    echo -e "${GREEN}Old backups will be automatically deleted after 7 days.${NC}"
    echo "$(date -Iseconds) - Phase6 complete" >> "$LOGFILE"
}

# --- Phase 7: Setup Auto Updates ---
setup_auto_updates() {
    echo -e "${GREEN}[7/8] Setting up automatic security updates...${NC}"
    echo "$(date -Iseconds) - Phase7: setup_auto_updates start" >> "$LOGFILE"

    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        wait_for_apt; apt-get update && apt-get install -y unattended-upgrades
        dpkg-reconfigure -f noninteractive unattended-upgrades
    else
        if command -v dnf &>/dev/null; then
            dnf install -y dnf-automatic
            systemctl enable --now dnf-automatic.timer
        else
            yum install -y yum-cron
            systemctl enable --now yum-cron
        fi
    fi

    echo -e "${GREEN}Auto updates setup complete.${NC}"
    echo "$(date -Iseconds) - Phase7 complete" >> "$LOGFILE"
}

# --- Phase 8: Deploy Sample Container ---
deploy_sample_container() {
    echo -e "${GREEN}[8/8] Deploying a sample container...${NC}"
    echo "$(date -Iseconds) - Phase8: deploy_sample_container start" >> "$LOGFILE"

    if ! command -v docker &>/dev/null; then
        echo -e "${RED}Docker is not installed. Please run Phase 4 first.${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Which sample container would you like to deploy?${NC}"
    select container_choice in "Nginx Web Server" "Portainer (Docker UI)"; do
        case $container_choice in
            "Nginx Web Server")
                deploy_nginx
                break
                ;;
            "Portainer (Docker UI)")
                deploy_portainer
                break
                ;;
            *)
                echo "Invalid option. Please choose 1 or 2."
                ;;
        esac
    done
    echo "$(date -Iseconds) - Phase8 complete" >> "$LOGFILE"
}

deploy_nginx() {
    echo -e "${YELLOW}Deploying Nginx using Docker Compose...${NC}"
    mkdir -p /opt/dockshield/nginx
    
    cat > /opt/dockshield/nginx/docker-compose.yml << EOF
services:
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      # To use SSL, uncomment below and update nginx.conf
      # - /etc/letsencrypt/live/yourdomain.com:/etc/letsencrypt:ro
    restart: unless-stopped
EOF

    cat > /opt/dockshield/nginx/nginx.conf << EOF
events {}
http {
    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;
        location / {
            try_files \$uri \$uri/ =404;
        }
    }
}
EOF
    
    (cd /opt/dockshield/nginx && docker compose up -d) || { echo -e "${RED}Failed to start Nginx.${NC}"; return 1; }
    echo -e "${GREEN}Nginx container is running. Access it at http://your-server-ip${NC}"
    echo -e "${YELLOW}To enable SSL, edit nginx.conf and docker-compose.yml in /opt/dockshield/nginx.${NC}"
    echo "$(date -Iseconds) - Nginx container deployed" >> "$LOGFILE"
}

deploy_portainer() {
    echo -e "${YELLOW}Deploying Portainer CE...${NC}"
    PORTAINER_PORT=9443
    
    read -r -p "${YELLOW}Portainer runs on port $PORTAINER_PORT. Open this port in the firewall? (y/n): ${NC}" OPEN_PORT
    if [[ "$OPEN_PORT" =~ ^[yY]$ ]]; then
        if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
            ufw allow $PORTAINER_PORT/tcp
            ufw reload
        else
            firewall-cmd --permanent --add-port=${PORTAINER_PORT}/tcp
            firewall-cmd --reload
        fi
        echo -e "${GREEN}Port $PORTAINER_PORT opened in firewall.${NC}"
        echo "$(date -Iseconds) - Opened port $PORTAINER_PORT for Portainer" >> "$LOGFILE"
    fi

    docker volume create portainer_data
    docker run -d \
        -p 8000:8000 \
        -p $PORTAINER_PORT:9443 \
        --name portainer \
        --restart=always \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        portainer/portainer-ce:latest || { echo -e "${RED}Failed to start Portainer.${NC}"; return 1; }
        
    echo -e "${GREEN}Portainer is running!${NC}"
    echo -e "${GREEN}Access the setup UI at: https://your-server-ip:$PORTAINER_PORT${NC}"
    echo -e "${YELLOW}(You will need to accept the self-signed certificate in your browser).${NC}"
    echo "$(date -Iseconds) - Portainer container deployed" >> "$LOGFILE"
}


# --- Run All Phases ---
run_all_phases() {
    echo -e "${GREEN}Running all phases sequentially...${NC}"
    echo "$(date -Iseconds) - Running all phases" >> "$LOGFILE"

    secure_server && \
    configure_firewall && \
    harden_ssh && \
    install_docker && \
    setup_ssl && \
    setup_backups && \
    setup_auto_updates && \
    deploy_sample_container
}

# --- Interactive CLI Menu ---
PS3="${YELLOW}Select an option: ${NC}"
options=(
    "Run All Phases (Recommended for new servers)"
    "1. Setup Secure User"
    "2. Configure Firewall"
    "3. Harden SSH"
    "4. Install Docker"
    "5. Setup SSL Certificates"
    "6. Setup Daily Backups"
    "7. Setup Auto Updates"
    "8. Deploy Sample Container (Nginx/Portainer)"
    "Exit"
)

select opt in "${options[@]}"; do
    case $opt in
        "Run All Phases (Recommended for new servers)")
            run_all_phases
            break
            ;;
        "1. Setup Secure User") secure_server ;;
        "2. Configure Firewall") configure_firewall ;;
        "3. Harden SSH") harden_ssh ;;
        "4. Install Docker") install_docker ;;
        "5. Setup SSL Certificates") setup_ssl ;;
        "6. Setup Daily Backups") setup_backups ;;
        "7. Setup Auto Updates") setup_auto_updates ;;
        "8. Deploy Sample Container (Nginx/Portainer)") deploy_sample_container ;;
        "Exit")
            echo -e "${GREEN}Exiting DockShield. Goodbye!${NC}"
            break
            ;;
        *)
            echo -e "${RED}Invalid option. Please select a number from 1 to ${#options[@]}.${NC}"
            ;;
    esac
done

echo ""
echo -e "${GREEN}=== DockShield script has finished. ===${NC}"
echo "$(date -Iseconds) - Script finished." >> "$LOGFILE"
