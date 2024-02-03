#!/bin/bash
# This is a bash script for setting Raspi-Cloud

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

# Update package lists and install Apache Server, a key component for the web server
sudo apt-get update
sudo apt-get install -y apache2

# Use rsync to synchronize the content of the 'html' directory from the cloned repo to the web server directory
sudo rsync -av --delete "$SCRIPT_DIRECTORY/html/" /var/www/html/

# Install Python3 and the virtual environment package, essential for running Python applications
sudo apt-get install -y python3 python3-venv

# Install Python pip, a package manager for Python packages
sudo apt-get install -y python3-pip

# Create a Python virtual environment for isolated package management
python3 -m venv $SCRIPT_DIRECTORY/venv
source $SCRIPT_DIRECTORY/venv/bin/activate

# Install necessary Python libraries for the cloud application
pip3 install Flask Flask-Bcrypt Flask-JWT-Extended Werkzeug flask-cors watchdog Flask-Limiter Flask-JWT-Extended redis
pip install python-dotenv

# Install SQLite3, a lightweight database, usually pre-installed on most systems
sudo apt-get install -y sqlite3

# Start the main server script in the background, ensuring continuous operation
nohup python3 /var/www/html/server.py > /dev/null 2>&1 &

# Start a background monitoring script, possibly for live updates or logging
nohup python3 $SCRIPT_DIRECTORY/watcher.py > /dev/null 2>&1 &

# Configure git to safely interact with the specified directory
git config --global --add safe.directory "$SCRIPT_DIRECTORY"
git config pull.rebase false

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
echo "Installation complete."