# DockShield : Automated Secure Server Deployment with Docker Integration

## Overview
DockShield is an automated script to deploy a secure production-ready server environment with Docker integration. It applies essential security configurations, firewall rules, SSH hardening, SSL encryption, and more — all in a single command.

## Features
- Creates a secure non-root user
- Disables root SSH login
- Configures firewall for essential services
- Hardens SSH access
- Installs Docker & Docker Compose
- Sets up SSL certificates
- Extensible for custom Dockerized applications

## Usage
```bash
git clone https://github.com/<your-username>/DockShield.git
cd DockShield
chmod +x deploy.sh
sudo ./deploy.sh
