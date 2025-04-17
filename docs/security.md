# Security Guide

This document provides comprehensive security guidelines and best practices for the FreeRADIUS TOTP Management System.

## Table of Contents

- [Overview](#overview)
- [Security Architecture](#security-architecture)
- [Network Security](#network-security)
  - [Firewall Configuration](#firewall-configuration)
  - [Network Segmentation](#network-segmentation)
  - [VPN Access](#vpn-access)
- [Container Security](#container-security)
  - [Principle of Least Privilege](#principle-of-least-privilege)
  - [Container Hardening](#container-hardening)
  - [Image Security](#image-security)
- [Authentication Security](#authentication-security)
  - [Password Policies](#password-policies)
  - [Two-Factor Authentication](#two-factor-authentication)
  - [Session Management](#session-management)
- [API Security](#api-security)
  - [API Authentication](#api-authentication)
  - [Rate Limiting](#rate-limiting)
  - [Input Validation](#input-validation)
- [Data Security](#data-security)
  - [Data Encryption](#data-encryption)
  - [Database Security](#database-security)
  - [Sensitive Data Handling](#sensitive-data-handling)
- [SSL/TLS Configuration](#ssltls-configuration)
  - [Certificate Management](#certificate-management)
  - [Cipher Suites](#cipher-suites)
  - [HSTS Implementation](#hsts-implementation)
- [Audit and Logging](#audit-and-logging)
  - [Audit Trail](#audit-trail)
  - [Log Management](#log-management)
  - [Log Analysis](#log-analysis)
- [Security Monitoring](#security-monitoring)
  - [Intrusion Detection](#intrusion-detection)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Security Updates](#security-updates)
- [Incident Response](#incident-response)
  - [Incident Detection](#incident-detection)
  - [Incident Handling](#incident-handling)
  - [Recovery Procedures](#recovery-procedures)
- [Compliance Considerations](#compliance-considerations)
  - [Regulatory Compliance](#regulatory-compliance)
  - [Security Standards](#security-standards)
  - [Privacy Regulations](#privacy-regulations)
- [Security Checklist](#security-checklist)

## Overview

The FreeRADIUS TOTP Management System handles sensitive authentication data and provides critical authentication services. As such, security is a paramount concern. This guide provides comprehensive security recommendations to protect the system from various threats.

## Security Architecture

The system's security architecture is built on the following principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Principle of Least Privilege**: Minimal access rights for components
3. **Secure by Default**: Secure default configurations
4. **Fail Secure**: Fail in a secure state
5. **Complete Mediation**: Verify every access to resources

The security architecture includes:

- Network security controls (firewalls, network segmentation)
- Container security (hardened containers, minimal images)
- Authentication security (strong passwords, TOTP)
- Data security (encryption, secure storage)
- Audit and logging (comprehensive audit trail)
- Monitoring and alerting (real-time security monitoring)

## Network Security

### Firewall Configuration

Configure a host-based firewall to restrict access to only the necessary ports:

```bash
# Allow SSH (consider changing to a non-standard port)
ufw allow 22/tcp

# Allow RADIUS authentication and accounting
ufw allow 1812/udp
ufw allow 1813/udp

# Allow Web UI (if not behind a reverse proxy)
ufw allow 8080/tcp

# Allow HTTPS (if using a reverse proxy)
ufw allow 443/tcp

# Deny all other incoming traffic
ufw default deny incoming

# Allow all outgoing traffic
ufw default allow outgoing

# Enable the firewall
ufw enable
```

For production environments, consider using a dedicated hardware firewall or cloud security group in addition to host-based firewalls.

### Network Segmentation

Implement network segmentation to isolate the authentication system:

1. **DMZ for Web UI**: Place the Web UI in a DMZ if it needs to be accessible from the internet
2. **Internal Network for RADIUS**: Place the RADIUS server in an internal network
3. **Management Network**: Use a separate management network for administrative access

Example Docker network configuration:

```yaml
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
  backend:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.28.1.0/24
  management:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.28.2.0/24
```

### VPN Access

Restrict administrative access to the system through a VPN:

1. **Set Up a VPN Server**: Use OpenVPN, WireGuard, or a similar solution
2. **Client Certificates**: Use client certificates for VPN authentication
3. **Two-Factor Authentication**: Enable 2FA for VPN access
4. **IP Restrictions**: Restrict Web UI access to VPN IP ranges

Example NGINX configuration for IP restrictions:

```nginx
location / {
    # Allow access only from VPN IP range
    allow 10.8.0.0/24;
    # Deny all other access
    deny all;
    
    proxy_pass http://localhost:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Container Security

### Principle of Least Privilege

Apply the principle of least privilege to container configurations:

1. **Non-Root User**: Run containers as non-root users

   ```yaml
   user: 1000:1000
   ```

2. **Capability Restrictions**: Drop unnecessary capabilities

   ```yaml
   cap_drop:
     - ALL
   cap_add:
     - NET_BIND_SERVICE
   ```

3. **Read-Only Filesystem**: Mount filesystems as read-only where possible

   ```yaml
   volumes:
     - type: bind
       source: ./config
       target: /etc/raddb
       read_only: true
   ```

4. **Temporary Filesystem**: Use tmpfs for temporary files

   ```yaml
   tmpfs:
     - /tmp
     - /var/run
   ```

### Container Hardening

Harden containers to reduce the attack surface:

1. **Minimal Base Images**: Use minimal base images like Alpine

   ```dockerfile
   FROM alpine:3.15
   ```

2. **Security Profiles**: Use security profiles to restrict container capabilities

   ```yaml
   security_opt:
     - no-new-privileges:true
     - seccomp:/path/to/seccomp/profile.json
   ```

3. **Resource Limits**: Set resource limits to prevent resource exhaustion

   ```yaml
   deploy:
     resources:
       limits:
         cpus: '0.5'
         memory: 512M
   ```

4. **Health Checks**: Implement health checks to detect and recover from failures

   ```yaml
   healthcheck:
     test: ["CMD", "/usr/local/bin/healthcheck.sh"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 15s
   ```

### Image Security

Secure container images to prevent supply chain attacks:

1. **Image Scanning**: Scan images for vulnerabilities

   ```bash
   docker scan freeradius-totp
   ```

2. **Image Signing**: Sign and verify images

   ```bash
   # Sign an image
   docker trust sign freeradius-totp:latest
   
   # Enable content trust
   export DOCKER_CONTENT_TRUST=1
   ```

3. **Minimal Dependencies**: Include only necessary dependencies

   ```dockerfile
   # Install only required packages
   RUN apk add --no-cache freeradius freeradius-sqlite
   ```

4. **Multi-Stage Builds**: Use multi-stage builds to reduce image size

   ```dockerfile
   # Build stage
   FROM alpine:3.15 AS build
   
   # ... build steps ...
   
   # Final stage
   FROM alpine:3.15
   COPY --from=build /app/build /app
   ```

## Authentication Security

### Password Policies

Implement strong password policies:

1. **Minimum Length**: Require passwords of at least 12 characters
2. **Complexity**: Require a mix of uppercase, lowercase, numbers, and special characters
3. **Password History**: Prevent reuse of previous passwords
4. **Maximum Age**: Require password changes every 90 days
5. **Account Lockout**: Lock accounts after multiple failed attempts

Example password policy implementation:

```python
def validate_password(password):
    """Validate password against policy"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets policy requirements"
```

### Two-Factor Authentication

Enforce two-factor authentication for all administrative access:

1. **TOTP for Administrators**: Require TOTP for all administrative users
2. **TOTP for API Access**: Consider requiring TOTP for API access
3. **Backup Codes**: Provide backup codes for emergency access
4. **Device Management**: Allow administrators to manage their authenticated devices

### Session Management

Implement secure session management:

1. **Session Timeout**: Set appropriate session timeouts (e.g., 15-30 minutes)
2. **Secure Cookies**: Use secure, HttpOnly, and SameSite cookies

   ```python
   app.config['SESSION_COOKIE_SECURE'] = True
   app.config['SESSION_COOKIE_HTTPONLY'] = True
   app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
   ```

3. **CSRF Protection**: Implement CSRF tokens for all state-changing operations

   ```python
   from flask_wtf.csrf import CSRFProtect
   
   csrf = CSRFProtect()
   csrf.init_app(app)
   ```

4. **Session Invalidation**: Invalidate sessions on logout and password change

## API Security

### API Authentication

Secure API access with strong authentication:

1. **API Keys**: Use API keys for authentication

   ```python
   def authenticate_api_request():
       api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
       if not api_key:
           return False, "API key is required"
       
       # Validate API key
       if not validate_api_key(api_key):
           return False, "Invalid API key"
       
       return True, "API key is valid"
   ```

2. **Key Rotation**: Implement API key rotation
3. **Scoped Access**: Limit API key permissions to specific operations
4. **Key Expiration**: Set expiration dates for API keys

### Rate Limiting

Implement rate limiting to prevent abuse:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/users")
@limiter.limit("10 per minute")
def get_users():
    # ...
```

### Input Validation

Validate all API input to prevent injection attacks:

```python
def validate_input(data, schema):
    """Validate input against a schema"""
    try:
        jsonschema.validate(data, schema)
        return True, "Input is valid"
    except jsonschema.exceptions.ValidationError as e:
        return False, f"Input validation failed: {e.message}"
```

## Data Security

### Data Encryption

Encrypt sensitive data at rest and in transit:

1. **Transport Encryption**: Use TLS for all communications
2. **Database Encryption**: Encrypt the SQLite database

   ```bash
   # Create an encrypted database
   sqlcipher /path/to/radius.db
   
   # Set the encryption key
   PRAGMA key = 'your-encryption-key';
   
   # Export the database schema
   .schema
   ```

3. **Secret Management**: Securely manage encryption keys and secrets

   ```bash
   # Generate a random key
   openssl rand -hex 32 > encryption_key.txt
   
   # Set permissions
   chmod 600 encryption_key.txt
   ```

### Database Security

Secure the database to protect sensitive data:

1. **Least Privilege**: Use a database user with minimal permissions
2. **Regular Backups**: Implement regular database backups
3. **Integrity Checks**: Perform regular integrity checks

   ```bash
   sqlite3 /path/to/radius.db "PRAGMA integrity_check;"
   ```

4. **Query Parameterization**: Use parameterized queries to prevent SQL injection

   ```python
   def get_user(username):
       conn = sqlite3.connect(db_path)
       cursor = conn.cursor()
       cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
       return cursor.fetchone()
   ```

### Sensitive Data Handling

Handle sensitive data securely:

1. **Data Minimization**: Collect and store only necessary data
2. **Data Masking**: Mask sensitive data in logs and displays

   ```python
   def mask_password(password):
       return '*' * len(password)
   ```

3. **Secure Deletion**: Securely delete sensitive data when no longer needed

   ```python
   def secure_delete_file(path):
       # Overwrite the file with random data
       with open(path, 'wb') as f:
           f.write(os.urandom(os.path.getsize(path)))
       
       # Delete the file
       os.remove(path)
   ```

## SSL/TLS Configuration

### Certificate Management

Manage SSL/TLS certificates securely:

1. **Certificate Authority**: Use certificates from a trusted CA for production
2. **Certificate Renewal**: Automate certificate renewal

   ```bash
   # Set up automatic renewal with certbot
   echo "0 0 * * * certbot renew --quiet" | crontab -
   ```

3. **Private Key Protection**: Protect private keys with appropriate permissions

   ```bash
   chmod 600 /path/to/private.key
   ```

### Cipher Suites

Configure strong cipher suites:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_dhparam /path/to/dhparam.pem;
```

Generate strong DH parameters:

```bash
openssl dhparam -out /path/to/dhparam.pem 4096
```

### HSTS Implementation

Implement HTTP Strict Transport Security:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## Audit and Logging

### Audit Trail

Implement a comprehensive audit trail:

1. **User Actions**: Log all user actions

   ```python
   def log_admin_action(username, action, details):
       """Log an administrative action"""
       conn = sqlite3.connect(db_path)
       cursor = conn.cursor()
       cursor.execute(
           "INSERT INTO audit_log (admin_username, action, details, timestamp) VALUES (?, ?, ?, ?)",
           (username, action, details, datetime.now().isoformat())
       )
       conn.commit()
       conn.close()
   ```

2. **Authentication Events**: Log all authentication attempts
3. **System Events**: Log system events (startup, shutdown, configuration changes)
4. **API Access**: Log all API access

### Log Management

Manage logs securely:

1. **Centralized Logging**: Implement centralized logging
2. **Log Rotation**: Configure log rotation to manage log file sizes

   ```bash
   # /etc/logrotate.d/radius
   /var/log/radius/*.log {
       daily
       rotate 7
       compress
       delaycompress
       missingok
       notifempty
       create 0640 radius radius
       sharedscripts
       postrotate
           systemctl reload freeradius
       endscript
   }
   ```

3. **Log Protection**: Protect logs from unauthorized access and modification

### Log Analysis

Analyze logs for security events:

1. **Log Monitoring**: Monitor logs for suspicious activity
2. **Alert Generation**: Generate alerts for security events
3. **Regular Review**: Regularly review logs for security issues

## Security Monitoring

### Intrusion Detection

Implement intrusion detection:

1. **Host-Based IDS**: Install and configure a host-based IDS like OSSEC

   ```bash
   # Install OSSEC
   apt-get install ossec-hids-server
   
   # Configure OSSEC
   nano /var/ossec/etc/ossec.conf
   
   # Start OSSEC
   systemctl start ossec
   ```

2. **Network-Based IDS**: Consider a network-based IDS like Suricata
3. **File Integrity Monitoring**: Monitor critical files for changes

   ```bash
   # OSSEC file integrity monitoring configuration
   <syscheck>
     <directories check_all="yes">/etc/raddb</directories>
     <directories check_all="yes">/opt/radius-totp</directories>
   </syscheck>
   ```

### Vulnerability Scanning

Regularly scan for vulnerabilities:

1. **Container Scanning**: Scan container images for vulnerabilities

   ```bash
   docker scan freeradius-totp
   ```

2. **Host Scanning**: Scan the host for vulnerabilities

   ```bash
   # Install OpenVAS
   apt-get install openvas
   
   # Set up OpenVAS
   openvas-setup
   
   # Start a scan
   omp -u admin -w admin -C -n "Radius Server Scan" -t "Radius Server"
   ```

3. **Web Application Scanning**: Scan the Web UI for vulnerabilities

   ```bash
   # Install OWASP ZAP
   apt-get install zaproxy
   
   # Run a scan
   zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" http://localhost:8080
   ```

### Security Updates

Keep the system up to date:

1. **Operating System Updates**: Regularly update the operating system

   ```bash
   apt-get update
   apt-get upgrade
   ```

2. **Container Updates**: Regularly update container images

   ```bash
   docker-compose pull
   docker-compose up -d
   ```

3. **Application Updates**: Keep the application up to date

   ```bash
   git pull
   docker-compose build
   docker-compose up -d
   ```

## Incident Response

### Incident Detection

Detect security incidents:

1. **Monitoring**: Monitor for suspicious activity
2. **Alerting**: Set up alerts for potential incidents
3. **User Reporting**: Provide a mechanism for users to report security issues

### Incident Handling

Handle security incidents effectively:

1. **Containment**: Isolate affected systems
2. **Eradication**: Remove the cause of the incident
3. **Recovery**: Restore systems to normal operation
4. **Documentation**: Document the incident and response

### Recovery Procedures

Prepare for recovery from security incidents:

1. **Backup Restoration**: Restore from backups if necessary
2. **System Rebuilding**: Rebuild systems if compromised
3. **Post-Incident Review**: Review and improve security measures

## Compliance Considerations

### Regulatory Compliance

Consider relevant regulatory requirements:

1. **PCI DSS**: If processing payment card data
2. **HIPAA**: If processing healthcare data
3. **GDPR**: If processing data of EU residents
4. **SOX**: If part of a publicly traded company

### Security Standards

Align with security standards:

1. **NIST Cybersecurity Framework**
2. **ISO 27001**
3. **CIS Benchmarks**

### Privacy Regulations

Consider privacy regulations:

1. **Data Protection**: Implement appropriate data protection measures
2. **Privacy Notices**: Provide clear privacy notices
3. **Data Subject Rights**: Respect data subject rights

## Security Checklist

Use this checklist to verify security measures:

- [ ] **Network Security**
  - [ ] Firewall configured
  - [ ] Network segmentation implemented
  - [ ] VPN access for administration

- [ ] **Container Security**
  - [ ] Containers run as non-root
  - [ ] Unnecessary capabilities dropped
  - [ ] Read-only filesystems where possible
  - [ ] Resource limits set

- [ ] **Authentication Security**
  - [ ] Strong password policy enforced
  - [ ] Two-factor authentication enabled
  - [ ] Secure session management implemented

- [ ] **API Security**
  - [ ] API authentication implemented
  - [ ] Rate limiting configured
  - [ ] Input validation implemented

- [ ] **Data Security**
  - [ ] Transport encryption (TLS) configured
  - [ ] Sensitive data encrypted at rest
  - [ ] Database security measures implemented

- [ ] **SSL/TLS Configuration**
  - [ ] Strong cipher suites configured
  - [ ] HSTS implemented
  - [ ] Certificates from trusted CA

- [ ] **Audit and Logging**
  - [ ] Comprehensive audit trail implemented
  - [ ] Log rotation configured
  - [ ] Logs protected from unauthorized access

- [ ] **Security Monitoring**
  - [ ] Intrusion detection implemented
  - [ ] Regular vulnerability scanning
  - [ ] Security updates applied promptly

- [ ] **Incident Response**
  - [ ] Incident response plan documented
  - [ ] Recovery procedures tested
  - [ ] Post-incident review process established