# Raspi-Cloud

## Introduction

In an era where life is increasingly shifting to the digital realm, secure cloud solutions are paramount. Self-hosted clouds offer a safe alternative, keeping personal data on one's own server. Raspi-Cloud is a project aimed at developing a self-hosted cloud storage solution that operates efficiently even on slow internet connections and with limited computing power, particularly on a power-efficient Raspberry Pi. This project has successfully tackled the challenge of maintaining cloud functionality under slow internet conditions, considering security, functionality, and resource aspects. The implementation involves an Apache server, integrating libraries like Flask, SQLite databases, and JWT authentication, resulting in a secure cloud application. This allows users to safely upload, download, and manage files.

## Features

- **Lightweight and Fast:** Raspi-Cloud is designed to be both resource-efficient and fast, ensuring effective file synchronization and sharing with minimal resource usage.
- **Self-hosted Security:** With the data stored on your own server, you have complete control over your data, enhancing security and privacy.
- **Optimized for Slow Connections:** Specially designed to function smoothly even with slow internet connections.
- **Raspberry Pi Compatibility:** Runs efficiently on Raspberry Pi, making it an ideal solution for energy-saving setups.

## Installation

### 1. Cloning and Installation

```bash
sudo apt-get install -y git
git clone git@github.com:JanisJ4/raspi-cloud.git
cd raspi-cloud
sudo bash install_script.sh 
```

### 2. Starting the Server

The server will start automatically and is configured to run on system startup.

### 3. Automatic Updates

The folder is monitored in the background, and updates from the master branch are automatically applied.

### 4. Firewall Configuration

If the cloud needs to be accessible over the internet, adjust firewall settings to forward requests on ports 80 (HTTP) (or 443 for HTTPS) and 8080.

## Setting Up HTTPS

### 1. Enabling SSL Module

```bash
sudo a2enmod ssl
```

### 2. Creating SSL Certificate

Use Let's Encrypt for a free SSL certificate:

```bash
sudo apt-get install certbot python3-certbot-apache
sudo certbot --apache
```

Follow Certbot instructions to create and configure your certificate.

### 3. Configuring Virtual Hosts

Edit your Apache virtual hosts to enable HTTPS. Add or modify lines to enable HTTPS.

Example:

```apache
<VirtualHost *:443>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ServerName yourdomain.com
    SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
```

### 4. Opening HTTPS Port in Firewall

```bash
sudo ufw allow 443/tcp
```

### 5. SSL Certificate Configuration in Installation Script

Add the following to your installation script for Raspi-Cloud:

```bash
# Set SSL certificate permissions
sudo groupadd ssl-cert
sudo usermod -a -G ssl-cert username
sudo chgrp ssl-cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem
sudo chgrp ssl-cert /etc/letsencrypt/live/yourdomain.com/privkey.pem
sudo chmod 640 /etc/letsencrypt/live/yourdomain.com/fullchain.pem
sudo chmod 640 /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

Replace `yourdomain.com` with your domain and `username` with your username.

### 6. Restart Apache

```bash
sudo reboot
```

Your cloud should now function with HTTPS. Ensure your domain points to your device's IP address to access the HTTPS version of your site.

## Notes

- Ensure the Raspberry Pi has an internet connection for downloading packages.
- The installation script can be modified as needed.