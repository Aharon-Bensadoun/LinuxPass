# LinuxPass

LinuxPass is a .NET Core application designed to manage users on Linux servers using SSH keys. It provides a centralized interface for storing and managing SSH credentials using encryption keys, simplifying user access control.

## Table of Contents

*   [Getting Started](#getting-started)
    *   [1. Fork the Repository](#1-fork-the-repository)
    *   [2. Configure `appsettings.json`](#2-configure-appsettingsjson)
    *   [3. Build the Project](#3-build-the-project)
    *   [4. Publish to Linux Container](#4-publish-to-linux-container)
    *   [5. Import Container Image](#5-import-container-image)
*   [Prerequisites on the Linux Server](#prerequisites-on-the-linux-server)
    *   [SQL Database](#sql-database)
    *   [SSH Key Generation](#ssh-key-generation)
    *   [PFX Directory and Certificate](#pfx-directory-and-certificate)
    *   [Deployment Script (`deploy.sh`)](#deployment-script-deploysh)
*   [Deployment](#deployment)


## Getting Started

### 1. Fork the Repository

Begin by forking the LinuxPass repository to your own GitHub account.

### 2. Configure `appsettings.json`

Modify the `appsettings.json` file with the necessary parameters:

*   `ConnectionString`: The connection string for your SQL database.
*   `EncryptionKey`: Your encryption key, converted to Base64. This key is crucial for securely storing passwords.
*   `AzureAD`: Settings for Azure Active Directory authentication (if applicable).
*   `SshKeyPath`: The path to the SSH key *within* the Docker container. This is typically `/app/id_rsa` after the key is copied in during deployment.
*   `Sms`: Settings for SMS integration (if applicable).

### 3. Build the Project

Build the .NET Core project using the following command:

```bash
dotnet build
```

### 4. Publish to Linux Container
Publish the application to a Linux container image:
```bash
dotnet publish --os linux --arch x64 /t:PublishContainer -p ContainerArchiveOutputPath=./images/container-image.tar.gz
```

### 5. Import Container Image
Import the generated container image into your Linux server:
```bash
docker load -i ./images/container-image.tar.gz
```
### Prerequisites on the Linux Server
Before deploying the container, ensure the following prerequisites are met on your Linux server:

### SQL Database
#### Create an SQL database and the required tables using the following SQL script:
```bash
IF NOT EXISTS(SELECT * FROM sys.databases WHERE name = 'linuxpass')
    BEGIN
        CREATE DATABASE linuxpass
    END
GO
    USE linuxpass
GO
--You need to check if the table exists
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Passwords' and xtype='U')
    BEGIN
        CREATE TABLE Passwords (
            Id INT IDENTITY(1,1) PRIMARY KEY,
            username VARCHAR(15) NOT NULL,
            servername VARCHAR(15) NOT NULL,
            encrypted_password VARCHAR(max) NOT NULL,
            add_time DATETIME NOT NULL );
    END

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Servers' and xtype='U')
    BEGIN
        CREATE TABLE Servers (
            Id INT PRIMARY KEY,
            HostSrvName VARCHAR(max) NOT NULL,
            HostSrvUsername VARCHAR(max) NOT NULL,
            HostSrvPassword VARCHAR(max),
            HostSSHKeyPath VARCHAR(max) );
    END
```

#### SSH Key Generation
Generate an SSH key pair on your Linux server:
```bash
ssh-keygen -t rsa
```

#### PFX Directory and Certificate
Create the necessary directories and either generate a self-signed PFX certificate or import an existing one. This is used for HTTPS.

```bash
mkdir -p ~/.aspnet/https
mv docker.pfx ~/.aspnet/https  # If you have a docker.pfx, otherwise generate/import one.
# Example using openssl to create a self-signed certificate (replace with your desired details):
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 \
    -subj "/C=US/ST=Example/L=Example/O=Example/CN=localhost"
openssl pkcs12 -export -out ~/.aspnet/https/linuxpass.pfx -inkey key.pem -in cert.pem -passin "A123456a" -passout "A123456a"
```
#### Deployment Script (deploy.sh)
Create a deploy.sh script with the following content (and make it executable: chmod +x deploy.sh):
```bash
#!/bin/bash
# Create and deploy the container

# Function to run a command and check for errors
run_command() {
    echo "Running: $1"
    if ! $1; then
        echo "Error occurred while executing: $1"
        exit 1
    fi
}

# Load the image from the tar file
if [ -f "container-image.tar.gz" ]; then
    run_command "docker load -i container-image.tar.gz"
else
    echo "Error: container-image.tar.gz file not found."
    exit 1
fi

# Run the container with the specified environment variables and ports
run_command "docker run -d -p 443:443 -p 80:80 \
    -e ASPNETCORE_URLS='https://+;http://+' \
    -e ASPNETCORE_HTTPS_PORTS=443 \
    -e ASPNETCORE_Kestrel__Certificates__Default__Password='A123456a' \
    -e ASPNETCORE_Kestrel__Certificates__Default__Path=/https/linuxpass.pfx \
    -v \${HOME}/.aspnet/https:/https/ linuxpass"

# Get the new container ID
new_container_id=$(docker ps -q --filter ancestor=linuxpass)
if [ -z "$new_container_id" ]; then
    echo "Error: Failed to get the new container ID."
    exit 1
fi
echo "New container ID: $new_container_id"

# Copy SSH key and certificates to the new container
if [ -f ".ssh/id_rsa" ]; then
    run_command "docker cp .ssh/id_rsa $new_container_id:/app/id_rsa"
else
    echo "Error: .ssh/id_rsa file not found."
    exit 1
fi

# Execute bash in the new container as root user
run_command "sudo docker exec -it -u root $new_container_id bash -c 'chmod 754 /app/id_rsa && bash  && exit'"
```

