# Installation Guide

This guide provides detailed instructions for installing and configuring the FreeRADIUS TOTP Management System.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
  - [Standard Installation](#standard-installation)
  - [Development Installation](#development-installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [SSL/TLS Configuration](#ssltls-configuration)
  - [Custom Configuration](#custom-configuration)
- [Initial Setup](#initial-setup)
  - [First Login](#first-login)
  - [Changing Default Credentials](#changing-default-credentials)
  - [Creating Your First User](#creating-your-first-user)
  - [Setting Up Your First RADIUS Client](#setting-up-your-first-radius-client)
- [Verification](#verification)
  - [Testing the Web UI](#testing-the-web-ui)
  - [Testing RADIUS Authentication](#testing-radius-authentication)
  - [Testing TOTP Authentication](#testing-totp-authentication)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before installing the FreeRADIUS TOTP Management System, ensure your system meets the following requirements:

### Hardware Requirements

- **CPU**: 1 core minimum (2+ cores recommended)
- **RAM**: 1 GB minimum (2+ GB recommended)
- **Disk Space**: 10 GB minimum (20+ GB recommended)
- **Network**: Stable network connection with access to required ports

### Software Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+) or macOS 12+
- **Docker**: Version 20.10.0 or higher
- **Docker Compose**: Version 2.0.0 or higher
- **Web Browser**: Chrome, Firefox, Safari, or Edge (latest versions)

### Network Requirements

The following ports need to be accessible:

- **1812/UDP**: RADIUS authentication
- **1813/UDP**: RADIUS accounting
- **8080/TCP**: Web UI

## Installation Methods

### Standard Installation

This is the recommended method for most users.

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/freeradius-totp-management.git
   cd freeradius-totp-management
   ```

2. **Generate SSL Certificates (Optional but Recommended)**

   ```bash
   ./certs/generate-certs.sh
   ```

   This script generates self-signed SSL certificates for development and testing. For production, replace these with certificates from a trusted CA.

3. **Configure Environment Variables (Optional)**

   Create a `.env` file in the project root directory to customize the configuration:

   ```bash
   # Example .env file
   TZ=America/New_York
   ADMIN_USER=myadmin
   ADMIN_PASSWORD_HASH=mypassword
   USE_SSL=true
   ```

   See the [Configuration](#configuration) section for all available options.

4. **Start the Containers**

   ```bash
   docker-compose up -d
   ```

   This command builds and starts the containers in detached mode.

5. **Verify Installation**

   ```bash
   docker-compose ps
   ```

   Ensure all containers are running and healthy.

6. **Access the Web UI**

   Open your web browser and navigate to:
   - http://localhost:8080 (if SSL is disabled)
   - https://localhost:8080 (if SSL is enabled)

### Development Installation

This method is recommended for developers who want to modify the system.

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/freeradius-totp-management.git
   cd freeradius-totp-management
   ```

2. **Create Development Environment**

   ```bash
   # Create a development .env file
   cat > .env << EOF
   TZ=UTC
   ADMIN_USER=admin
   ADMIN_PASSWORD_HASH=changeme
   USE_SSL=false
   EOF
   ```

3. **Start the Containers with Development Configuration**

   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
   ```

   This uses an additional development configuration that enables:
   - Volume mounting of source code for live editing
   - Debug logging
   - Hot reloading for the Flask application

4. **Access the Web UI**

   Open your web browser and navigate to http://localhost:8080

## Configuration

### Environment Variables

The system can be configured using environment variables, either by setting them in your shell or by creating a `.env` file in the project root directory.

#### FreeRADIUS Container

| Variable | Description | Default |
|----------|-------------|---------|
| `TZ` | Timezone | `UTC` |
| `SQLITE_DB` | Path to SQLite database | `/data/sqlite/radius.db` |

#### Web UI Container

| Variable | Description | Default |
|----------|-------------|---------|
| `TZ` | Timezone | `UTC` |
| `SQLITE_DB` | Path to SQLite database | `/data/sqlite/radius.db` |
| `ADMIN_USER` | Default admin username | `admin` |
| `ADMIN_PASSWORD_HASH` | Default admin password hash | `changeme` |
| `USE_SSL` | Enable SSL | `false` |
| `SSL_CERT` | Path to SSL certificate | `/app/ssl/server.crt` |
| `SSL_KEY` | Path to SSL private key | `/app/ssl/server.key` |
| `BACKUP_DIR` | Path to backup directory | `/data/backups` |
| `SECRET_KEY` | Flask secret key | `dev-key-change-in-production` |

### SSL/TLS Configuration

To enable SSL/TLS for secure HTTPS communication:

1. **Generate or Obtain SSL Certificates**

   For development or testing, you can use the included script to generate self-signed certificates:

   ```bash
   ./certs/generate-certs.sh
   ```

   For production, obtain certificates from a trusted Certificate Authority (CA).

2. **Configure SSL in the Environment**

   Set the following environment variables:

   ```bash
   USE_SSL=true
   SSL_CERT=/app/ssl/server.crt
   SSL_KEY=/app/ssl/server.key
   ```

3. **Restart the Containers**

   ```bash
   docker-compose down
   docker-compose up -d
   ```

4. **Access the Web UI via HTTPS**

   Open your web browser and navigate to https://localhost:8080

### Custom Configuration

For advanced configuration, you can modify the following files:

#### FreeRADIUS Configuration

- `freeradius/config/radiusd.conf`: Main FreeRADIUS configuration
- `freeradius/config/clients.conf`: RADIUS client configuration
- `freeradius/config/mods-available/sql`: Database connection settings
- `freeradius/config/mods-available/totp`: TOTP module settings

#### Web UI Configuration

- `webui/app/app.py`: Flask application configuration
- `webui/app/models.py`: Database models
- `webui/app/routes.py`: Route definitions
- `webui/app/api_routes.py`: API endpoint definitions

## Initial Setup

### First Login

1. Access the Web UI at http://localhost:8080 (or https://localhost:8080 if SSL is enabled)
2. Log in with the default credentials:
   - Username: `admin` (or the value of `ADMIN_USER`)
   - Password: `changeme` (or the value of `ADMIN_PASSWORD_HASH`)

### Changing Default Credentials

1. After logging in, click on "My Profile" in the sidebar
2. Click on "Change Password"
3. Enter your current password and a new password
4. Click "Update Password"

### Creating Your First User

1. Navigate to "User Management" in the sidebar
2. Click "Create User"
3. Fill in the user details:
   - Username: The username for RADIUS authentication
   - Password: The user's password
   - Enable TOTP: Check this to enable two-factor authentication
   - Groups: Optional group memberships (comma-separated)
4. Click "Create User"
5. If TOTP is enabled, you'll be redirected to the TOTP setup page:
   - Scan the QR code with Google Authenticator or a compatible app
   - Enter the verification code from the app
   - Click "Verify"

### Setting Up Your First RADIUS Client

1. Navigate to "Client Management" in the sidebar
2. Click "Create Client"
3. Fill in the client details:
   - NAS Name: IP address or hostname of the RADIUS client
   - Short Name: A friendly name for the client
   - Type: The client type (e.g., cisco, juniper)
   - Secret: The shared secret for RADIUS authentication
   - Ports: The ports used by the client (default: 0)
   - Description: Optional description
4. Click "Create Client"

## Verification

### Testing the Web UI

1. Log out and log back in to verify your credentials work
2. Navigate to different sections of the Web UI to ensure they load correctly
3. Check the "Dashboard" to see system status information

### Testing RADIUS Authentication

You can test RADIUS authentication using the `radtest` utility:

```bash
docker-compose exec freeradius radtest testuser password localhost 0 testing123
```

Replace `testuser` and `password` with your user's credentials, and `testing123` with your RADIUS client's shared secret.

### Testing TOTP Authentication

To test TOTP authentication:

1. Create a user with TOTP enabled
2. Set up the TOTP token in Google Authenticator or a compatible app
3. Use the `radtest` utility with the password followed by the TOTP code:

```bash
docker-compose exec freeradius radtest testuser "password123456" localhost 0 testing123
```

Where `123456` is the current TOTP code from your authenticator app.

## Upgrading

To upgrade to a newer version of the system:

1. **Backup Your Data**

   ```bash
   # Create a backup directory
   mkdir -p backups
   
   # Backup the SQLite database
   docker-compose exec -T webui sqlite3 /data/sqlite/radius.db .dump > backups/radius_db_backup.sql
   
   # Backup configuration files
   docker-compose exec -T freeradius tar -czf - /etc/raddb > backups/raddb_config_backup.tar.gz
   ```

2. **Pull the Latest Changes**

   ```bash
   git pull origin main
   ```

3. **Rebuild and Restart the Containers**

   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

4. **Verify the Upgrade**

   ```bash
   docker-compose ps
   ```

   Ensure all containers are running and healthy.

## Troubleshooting

### Common Issues

#### Web UI Not Accessible

- **Check if containers are running:**
  ```bash
  docker-compose ps
  ```

- **Check container logs:**
  ```bash
  docker-compose logs webui
  ```

- **Verify network configuration:**
  ```bash
  docker-compose exec webui ping freeradius
  ```

#### Authentication Failures

- **Check FreeRADIUS logs:**
  ```bash
  docker-compose logs freeradius
  ```

- **Run FreeRADIUS in debug mode:**
  ```bash
  docker-compose stop freeradius
  docker-compose run --rm freeradius freeradius -X
  ```

- **Test authentication manually:**
  ```bash
  docker-compose exec freeradius radtest testuser password localhost 0 testing123
  ```

#### Database Issues

- **Check database connectivity:**
  ```bash
  docker-compose exec webui sqlite3 /data/sqlite/radius.db .tables
  ```

- **Verify database permissions:**
  ```bash
  docker-compose exec webui ls -la /data/sqlite
  ```

- **Check database integrity:**
  ```bash
  docker-compose exec webui sqlite3 /data/sqlite/radius.db "PRAGMA integrity_check;"
  ```

### Getting Help

If you encounter issues not covered in this guide:

1. Check the logs for error messages:
   ```bash
   docker-compose logs
   ```

2. Check the "Troubleshooting" section in the documentation

3. Open an issue on the GitHub repository with:
   - A description of the problem
   - Steps to reproduce
   - Relevant logs and error messages
   - Your system information (OS, Docker version, etc.)