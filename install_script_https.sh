#!/bin/bash
# This is a bash script for setting up Raspi-Cloud for production using Apache, mod_wsgi, and HTTPS

# Determine the directory where this installation script is located
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if the script is executed with root privileges, necessary for certain operations
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Please execute with sudo."
   exit 1
fi

# Ask for the domain name and save it to a configuration file
read -p "Enter your domain name (else nothing): " DOMAIN_NAME
echo "DOMAIN_NAME=$DOMAIN_NAME" > "/var/www/config.env"

# Update package lists and install Apache Server, mod_wsgi, and Certbot for Let's Encrypt
sudo apt-get update
sudo apt-get install -y apache2 libapache2-mod-wsgi-py3 python3-certbot-apache 

# Prepare WSGI file for Apache
WSGI_FILE="$SCRIPT_DIRECTORY/flaskapp.wsgi"
echo "import sys
sys.path.insert(0, '/var/www/html')
from server import app as application" > $WSGI_FILE

# Synchronize the content of the 'html' directory to the web server directory
sudo rsync -av --delete "$SCRIPT_DIRECTORY/html/" /var/www/html/

# Install Python3, Python virtual environment package, and Python pip
sudo apt-get install -y python3 python3-venv python3-pip

# Create a Python virtual environment and activate it
python3 -m venv $SCRIPT_DIRECTORY/venv
source $SCRIPT_DIRECTORY/venv/bin/activate

# Install necessary Python libraries for the cloud application
pip3 install Flask Flask-Bcrypt Flask-JWT-Extended Werkzeug Flask-Limiter Flask-JWT-Extended redis
pip3 install flask-cors
pip3 install watchdog
pip3 install python-dotenv

# Install SQLite3
sudo apt-get install -y sqlite3

# Configure git
git config --global --add safe.directory "$SCRIPT_DIRECTORY"
git config pull.rebase false

# Create Apache VirtualHost configuration for HTTPS
VHOST_CONF="/etc/apache2/sites-available/$DOMAIN_NAME.conf"
echo "<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName $DOMAIN_NAME
    WSGIDaemonProcess flaskapp python-home=$SCRIPT_DIRECTORY/venv python-path=/var/www/html
    WSGIProcessGroup flaskapp
    WSGIScriptAlias / $WSGI_FILE

    <Directory /var/www/html>
        Require all granted
    </Directory>

    Alias /static /var/www/html/static
    <Directory /var/www/html/static>
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/$DOMAIN_NAME_error.log
    CustomLog ${APACHE_LOG_DIR}/$DOMAIN_NAME_access.log combined

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>" > $VHOST_CONF

# Enable the site and SSL module
sudo a2ensite $DOMAIN_NAME.conf
sudo a2enmod ssl

# Reload Apache to apply changes
sudo systemctl reload apache2

# Obtain SSL certificates from Let's Encrypt using Certbot
sudo certbot --apache -d $DOMAIN_NAME
# Opening HTTPS Port in Firewall
sudo ufw allow 443/tcp

# Create a script to update the cloud content and make it executable
echo "/bin/bash -c 'date && cd $SCRIPT_DIRECTORY && git pull && sudo rsync -av --delete $SCRIPT_DIRECTORY/html/ /var/www/html/' 2>&1 | tee -a /var/log/Raspi-Cloud.log" > updateRaspi-Cloud
chmod +x updateRaspi-Cloud
mv updateRaspi-Cloud /usr/local/bin/

# Create a startup script for the cloud service and make it executable
echo "/bin/bash -c 'date && source $SCRIPT_DIRECTORY/venv/bin/activate && nohup python3 /var/www/html/server.py' && nohup python3 $SCRIPT_DIRECTORY/watcher.py 2>&1 | tee -a /var/log/Raspi-Cloud.log" > startRaspi-Cloud
chmod +x startRaspi-Cloud
mv startRaspi-Cloud /usr/local/bin/

# Schedule the update and startup scripts to run at reboot and periodically using crontab
(crontab -l; echo "@reboot /usr/local/bin/updateRaspi-Cloud") | sort -u | crontab -
(crontab -l; echo "@reboot /usr/local/bin/startRaspi-Cloud") | sort -u | crontab -
(crontab -l; echo "0 * * * * /usr/local/bin/updateRaspi-Cloud") | sort -u | crontab -

# Confirm the completion of the installation process
echo "Installation complete. Your domain name $DOMAIN_NAME has been configured for production with Apache, mod_wsgi, and HTTPS."
