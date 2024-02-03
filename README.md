# Raspi-Cloud

## Introduction

In an era where life is increasingly shifting to the digital realm, secure cloud solutions are paramount. Self-hosted clouds offer a safe alternative, keeping personal data on one's own server. Raspi-Cloud is a project aimed at developing a self-hosted cloud storage solution that operates efficiently even on slow internet connections and with limited computing power, particularly on a power-efficient Raspberry Pi. This project has successfully tackled the challenge of maintaining cloud functionality under slow internet conditions, considering security, functionality, and resource aspects. The implementation involves an Apache server, integrating libraries like Flask, SQLite databases, and JWT authentication, resulting in a secure cloud application. This allows users to safely upload, download, and manage files.

## Features

- **Lightweight and Fast:** Optimized for minimal resource usage while ensuring fast file synchronization and sharing capabilities.
- **Self-hosted Security:** Complete control over your data for enhanced security and privacy.
- **Optimized for Slow Connections:** Designed to function smoothly in low-bandwidth environments.
- **Raspberry Pi Compatibility:** Ideal for energy-efficient setups, running efficiently on Raspberry Pi devices.


## Experiments and Results

An analysis was conducted to compare the performance of the self-developed Raspi-Cloud solution against established cloud storage solutions like Nextcloud, particularly in scenarios with limited computational power and slow internet connections. The focus was on several key aspects:

- **Speed:** Time taken for uploading and downloading files.
- **Response Time:** The time between a request and the server's first response.
- **Efficiency:** CPU usage of the Raspberry Pi during various operations.

### Testing Conditions

To ensure fair and comparable conditions, the following parameters were kept constant:

- **Hardware:** Raspberry Pi 3b.
- **Operating System Version:** Raspbian GNU/Linux 12 (bookworm).
- **Network Conditions:** Same network environment and similar network load.

The tests were conducted using the web interfaces of both cloud solutions, with Firefox Browser version 120.0.1 (64-bit) as the testing tool.

### Speed and Response Time

Performance in file transfer was analyzed for different file sizes (1MB, 10MB, 100MB) by conducting five uploads and downloads for each file size and measuring the following times:

- **Connecting Time**
- **Waiting Time**
- **Sending Time** (for uploads)
- **Receiving Time** (for downloads)

#### Average Upload and Download Time

![Performance Graph](statistics/performance_graphs.png)

### Efficiency

To assess the efficiency, CPU usage was monitored during the file upload and download processes. Each test consisted of alternating five uploads and five downloads of a 100MB file, allowing for the collection of substantial data.

#### CPU Usage During Upload and Download

![Performance Graph](statistics/efficiency_graphs.png)

### Results and Analysis

The Raspi-Cloud demonstrated consistently higher performance and efficiency compared to Nextcloud. Notably, in uploading smaller files, Raspi-Cloud was significantly faster and more responsive. CPU utilization was substantially lower during both uploads and downloads, indicating greater efficiency. These results suggest that Raspi-Cloud is particularly well-suited for environments with limited computational resources and slower internet connections, outperforming Nextcloud in speed, response time, and efficiency.


## Installation

**Please read the entire section so as not to make any mistakes during setup and to avoid possible security risks.**

### Prerequisites

- Ensure your Raspberry Pi is running the latest version of its OS and has internet access.
- This guide assumes you have basic knowledge of Linux and the command line.

### 1. Cloning

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/JanisJ4/Raspi-Cloud.git
```
### Internet connection

If your cloud is to be accessible via the Internet, you must enable port 80 in your network if you want to use HTTP (**this is strongly discouraged**) and port 443 if you want to use HTTPS (note that you need your own domain for this). In both cases, port 8080 must be enabled. Make sure that the ports are configured with the correct protocol. 

### 2. Installation

#### HTTPS

To ensure secure communication and data transfer between the cloud and the connected devices, HTTPS must be configured.  Following the instructions provided is crucial for the successful setup of HTTPS. Please note that a separate domain is mandatory for the configuration of the SSL certificate. Without a domain, the HTTPS setup cannot be completed. To continue with the HTTPS installation, execute the following commands:

```bash 
cd Raspi-Cloud
sudo bash install_script_https.sh
```

#### HTTP

**Warning:** Using HTTP for your self-hosted cloud is less secure compared to HTTPS, as data transmitted over HTTP is not encrypted. This can expose sensitive information to potential interception by unauthorized parties. If you choose to proceed with HTTP, be aware of the security risks, especially if accessing your cloud over the internet. To continue with the HTTP installation, run the following commands:

```bash 
cd Raspi-Cloud
sudo bash install_script_http.sh
```

### 3. Accessing the Cloud Interface 

The cloud can be accessed through a web interface (for more, see Usage) using the local IP address of the Raspberry Pi if you are operating it within a local network via HTTP. However, for external access or for enhanced security, it's recommended to use a domain and HTTPS. Initially, setting up the cloud locally with HTTP can be a prudent step. This allows for the configuration of the first user, who will have owner privileges, in a more secure environment. Once the initial setup is complete and the first user is configured, you can then proceed to make the cloud accessible over the internet by executing the HTTPS installation script. This approach ensures that administrative access is secured before exposing the cloud to wider network access.

### 4. Updates and Maintenance 

While the cloud system is designed to update itself automatically, it's important to note that this auto-update feature may only apply to the cloud software itself. Other components of the system, such as the operating system and any additional installed software, will likely require manual updates to ensure they remain secure against vulnerabilities. Regular manual updates are essential to maintain the overall security and functionality of your cloud server, preventing potential security breaches and ensuring the system runs smoothly.


## Usage

Raspi-Cloud hosts a web interface, making it accessible through a browser. You can access your cloud by navigating to the domain that points to the device hosting Raspi-Cloud or directly via the device's IP address.

### First User and Ownership

The first user to log in to Raspi-Cloud becomes the owner. This initial login uses the credentials provided during setup. As the owner, you have full control over the cloud's settings, including user and group management.

### Solo Usage

If you plan to use Raspi-Cloud individually, you can start storing and managing your data immediately after the initial setup and login. The web interface provides straightforward options for uploading, downloading, and organizing your files.

### Multi-User Setup

If the cloud is to be used by multiple users, you can configure additional users and groups through the settings menu. Here's how:

- **Accessing Settings:** Navigate to the settings menu from the main interface.
- **Adding Users:** In the settings, there is an option to add new users. Each user will need their own set of login credentials.
- **Creating Groups:** Groups allow you to create collections of users that can be managed together. This is useful for organizing access rights and file sharing among a set of users.
- **Managing Access Rights:** The settings menu also allows you to define who has what level of access globally and within each group. This includes read, write, and administrative privileges.

### Groups and File Sharing

Groups are designed to simplify the management of file access among multiple users. By assigning users to groups, you can control which files are accessible to whom, ensuring that users only have access to the files they are meant to see and work with.

### Upcoming Android App

In the near future, Raspi-Cloud will also be accessible via an Android app, providing even more convenience and flexibility. This app will allow users to access their files on the go, making it easier to upload, download, and manage data directly from their Android devices. Stay tuned for updates on the app's release and features.

Remember to regularly check the settings to update any changes in user access or group configurations as your team or family needs evolve.

## Contributing

Contributions to Raspi-Cloud are highly appreciated, whether they come in the form of feature enhancements, bug fixes, documentation improvements, or other forms of support. Here's how you can contribute:

### How to Contribute

1. **Fork the Repository:** Begin by forking the Raspi-Cloud repository on GitHub.

2. **Clone the Fork:** Clone the fork to a local machine for development purposes.

   ```bash
   git clone git@github.com:JanisJ4/Raspi-Cloud.git
   cd Raspi-Cloud
   ```

3. **Create a New Branch:** Use a separate branch for each feature or fix, keeping the development organized.

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Implement Changes:** Work on the desired changes in the branch, ensuring thorough testing and adherence to coding standards.

5. **Commit Changes:** Commit the changes with a clear message, describing the modifications and their purpose.

   ```bash
   git commit -m "Describe your changes here"
   ```

6. **Push to Fork:** Push the branch to the fork on GitHub.

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Submit a Pull Request:** From the GitHub fork, submit a pull request. Clearly describe the changes and their benefits.

### Reporting Bugs and Suggesting Enhancements

- **Reporting Bugs:** For bug reports, open an issue on GitHub, detailing the bug, steps to reproduce, and any relevant logs or screenshots.

- **Suggesting Enhancements:** Enhancement suggestions are welcomed. Open an issue to discuss potential improvements, providing as much detail as possible.

### Community Guidelines

Respect and adherence to community guidelines are expected from all contributors. These guidelines foster a positive and productive environment for everyone.

### Staying Updated

Regularly synchronize the fork with the main repository to stay current with the latest developments, which helps in reducing merge conflicts and ensuring the contributions are up-to-date.

### Questions and Discussions

For questions or discussions about ideas and implementations, use the issue tracker. This encourages community feedback and collaborative problem-solving.

Raspi-Cloud appreciates all contributions and looks forward to seeing how the project evolves with the support of the open-source community.

## License

Raspi-Cloud is made available under the MIT License. This license allows for personal and commercial use, modification, distribution, and private use of the software, offering great flexibility to users and contributors.

While Raspi-Cloud itself is licensed under the MIT License, it also utilizes various libraries that are subject to their own licenses. Most of these libraries are licensed under MIT and Apache licenses, which are generally permissive. However, if you plan to use Raspi-Cloud for purposes beyond personal use, it is advised to review the licenses of these individual libraries to ensure compliance with their terms, especially in a commercial or enterprise environment.

The MIT License is concise and permissive, allowing for almost any use of the project, including the creation and distribution of closed source versions, as long as proper attribution is given to Raspi-Cloud and it is not held liable for any outcomes.

For the full terms and conditions of the MIT License, as well as a more detailed description, please refer to the [LICENSE.md](https://github.com/JanisJ4/Raspi-Cloud/blob/main/LICENSE) file in the project repository.