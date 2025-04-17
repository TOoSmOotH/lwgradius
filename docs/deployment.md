# Deployment Guide

This guide provides detailed instructions for deploying the FreeRADIUS TOTP Management System in various environments, from single-server setups to high-availability configurations.

## Table of Contents

- [Deployment Scenarios](#deployment-scenarios)
  - [Single-Server Deployment](#single-server-deployment)
  - [High-Availability Deployment](#high-availability-deployment)
  - [Production Considerations](#production-considerations)
- [System Requirements](#system-requirements)
  - [Hardware Requirements](#hardware-requirements)
  - [Software Requirements](#software-requirements)
  - [Network Requirements](#network-requirements)
- [Docker Compose Deployment](#docker-compose-deployment)
  - [Basic Deployment](#basic-deployment)
  - [Production Deployment](#production-deployment)
  - [Environment Configuration](#environment-configuration)
- [Docker Swarm Deployment](#docker-swarm-deployment)
  - [Swarm Initialization](#swarm-initialization)
  - [Service Deployment](#service-deployment)
  - [Scaling Services](#scaling-services)
  - [Rolling Updates](#rolling-updates)
- [Security Hardening](#security-hardening)
  - [Network Security](#network-security)
  - [Container Security](#container-security)
  - [Authentication Security](#authentication-security)
  - [SSL/TLS Configuration](#ssltls-configuration)
- [Monitoring and Logging](#monitoring-and-logging)
  - [Container Monitoring](#container-monitoring)
  - [Log Management](#log-management)
  - [Health Checks](#health-checks)
  - [Alerting](#alerting)
- [Backup and Recovery](#backup-and-recovery)
  - [Backup Strategy](#backup-strategy)
  - [Recovery Procedures](#recovery-procedures)
- [Scaling Guidelines](#scaling-guidelines)
  - [Vertical Scaling](#vertical-scaling)
  - [Horizontal Scaling](#horizontal-scaling)
  - [Database Scaling](#database-scaling)
- [Upgrade Procedures](#upgrade-procedures)
  - [Planning an Upgrade](#planning-an-upgrade)
  - [Performing the Upgrade](#performing-the-upgrade)
  - [Rollback Procedures](#rollback-procedures)

## Deployment Scenarios

### Single-Server Deployment

A single-server deployment is suitable for small to medium-sized organizations with moderate authentication requirements. In this scenario, all components run on a single physical or virtual server.

**Advantages:**
- Simple setup and maintenance
- Lower hardware requirements
- Easier troubleshooting

**Disadvantages:**
- Single point of failure
- Limited scalability
- Potential performance bottlenecks under heavy load

### High-Availability Deployment

A high-availability deployment is suitable for organizations with critical authentication requirements that need redundancy and fault tolerance. In this scenario, components are distributed across multiple servers in a Docker Swarm or similar orchestration platform.

**Advantages:**
- Redundancy and fault tolerance
- Better scalability
- Improved performance under heavy load

**Disadvantages:**
- More complex setup and maintenance
- Higher hardware requirements
- More complex troubleshooting

### Production Considerations

When deploying in a production environment, consider the following:

- **Security**: Implement proper security measures (see [Security Hardening](#security-hardening))
- **Monitoring**: Set up monitoring and alerting (see [Monitoring and Logging](#monitoring-and-logging))
- **Backup**: Implement a robust backup strategy (see [Backup and Recovery](#backup-and-recovery))
- **Scaling**: Plan for future growth (see [Scaling Guidelines](#scaling-guidelines))
- **Updates**: Establish procedures for updates and maintenance (see [Upgrade Procedures](#upgrade-procedures))

## System Requirements

### Hardware Requirements

#### Single-Server Deployment

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk Space | 20 GB | 50+ GB |
| Network | 100 Mbps | 1 Gbps |

#### High-Availability Deployment

| Component | Minimum per Node | Recommended per Node |
|-----------|------------------|----------------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk Space | 50 GB | 100+ GB |
| Network | 1 Gbps | 10 Gbps |
| Number of Nodes | 3 | 5+ |

### Software Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Docker**: Version 20.10.0 or higher
- **Docker Compose**: Version 2.0.0 or higher (for single-server deployment)
- **Docker Swarm**: (for high-availability deployment)
- **Reverse Proxy**: NGINX or similar (for SSL termination and load balancing)
- **Monitoring Tools**: Prometheus, Grafana, or similar (optional but recommended)

### Network Requirements

The following ports need to be accessible:

- **1812/UDP**: RADIUS authentication
- **1813/UDP**: RADIUS accounting
- **8080/TCP**: Web UI
- **2377/TCP**: Docker Swarm cluster management (for high-availability deployment)
- **7946/TCP/UDP**: Docker Swarm node communication (for high-availability deployment)
- **4789/UDP**: Docker Swarm overlay network (for high-availability deployment)

## Docker Compose Deployment

### Basic Deployment

For a basic single-server deployment:

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/freeradius-totp-management.git
   cd freeradius-totp-management
   ```

2. **Generate SSL Certificates**

   ```bash
   ./certs/generate-certs.sh
   ```

   For production, replace these with certificates from a trusted CA.

3. **Start the Containers**

   ```bash
   docker-compose up -d
   ```

4. **Verify Deployment**

   ```bash
   docker-compose ps
   ```

   Ensure all containers are running and healthy.

### Production Deployment

For a production-ready single-server deployment:

1. **Create a Production Configuration**

   Create a `.env` file with production settings:

   ```bash
   # Production .env file
   TZ=UTC
   ADMIN_USER=admin
   ADMIN_PASSWORD_HASH=your-secure-password-hash
   USE_SSL=true
   SECRET_KEY=your-random-secret-key
   ```

   Generate a secure random key for `SECRET_KEY`:

   ```bash
   openssl rand -hex 32
   ```

2. **Configure Resource Limits**

   Adjust the resource limits in `docker-compose.yml` based on your server's capabilities:

   ```yaml
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
   ```

3. **Set Up a Reverse Proxy (Optional but Recommended)**

   For better security and performance, set up NGINX as a reverse proxy:

   ```bash
   # Install NGINX
   apt-get update
   apt-get install -y nginx

   # Create NGINX configuration
   cat > /etc/nginx/sites-available/radius-totp << EOF
   server {
       listen 80;
       server_name your-domain.com;
       return 301 https://\$host\$request_uri;
   }

   server {
       listen 443 ssl;
       server_name your-domain.com;

       ssl_certificate /path/to/your/certificate.crt;
       ssl_certificate_key /path/to/your/private.key;
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_prefer_server_ciphers on;
       ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host \$host;
           proxy_set_header X-Real-IP \$remote_addr;
           proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto \$scheme;
       }
   }
   EOF

   # Enable the site
   ln -s /etc/nginx/sites-available/radius-totp /etc/nginx/sites-enabled/
   nginx -t
   systemctl reload nginx
   ```

4. **Start the Containers**

   ```bash
   docker-compose up -d
   ```

5. **Set Up Automatic Updates (Optional)**

   Create a script for automatic updates:

   ```bash
   cat > /usr/local/bin/update-radius-totp.sh << EOF
   #!/bin/bash
   cd /path/to/freeradius-totp-management
   git pull
   docker-compose down
   docker-compose up -d --build
   EOF

   chmod +x /usr/local/bin/update-radius-totp.sh
   ```

   Add a cron job to run the script weekly:

   ```bash
   echo "0 2 * * 0 /usr/local/bin/update-radius-totp.sh >> /var/log/radius-totp-update.log 2>&1" | crontab -
   ```

### Environment Configuration

The system can be configured using environment variables in a `.env` file:

```bash
# General Settings
TZ=UTC                                  # Timezone
ADMIN_USER=admin                        # Default admin username
ADMIN_PASSWORD_HASH=secure-password     # Default admin password
SECRET_KEY=random-secret-key            # Flask secret key

# SSL/TLS Settings
USE_SSL=true                            # Enable SSL
SSL_CERT=/app/ssl/server.crt            # Path to SSL certificate
SSL_KEY=/app/ssl/server.key             # Path to SSL private key

# Database Settings
SQLITE_DB=/data/sqlite/radius.db        # Path to SQLite database

# Backup Settings
BACKUP_DIR=/data/backups                # Path to backup directory

# Resource Limits
FREERADIUS_CPU_LIMIT=0.5                # CPU limit for FreeRADIUS container
FREERADIUS_MEMORY_LIMIT=512M            # Memory limit for FreeRADIUS container
WEBUI_CPU_LIMIT=0.5                     # CPU limit for WebUI container
WEBUI_MEMORY_LIMIT=512M                 # Memory limit for WebUI container
```

## Docker Swarm Deployment

### Swarm Initialization

For a high-availability deployment using Docker Swarm:

1. **Initialize the Swarm on the First Node**

   ```bash
   docker swarm init --advertise-addr <MANAGER-IP>
   ```

   This command outputs a token for joining worker nodes.

2. **Join Worker Nodes to the Swarm**

   On each worker node, run the command output by the previous step:

   ```bash
   docker swarm join --token <TOKEN> <MANAGER-IP>:2377
   ```

3. **Verify the Swarm**

   On the manager node:

   ```bash
   docker node ls
   ```

   Ensure all nodes are listed and have the "Ready" status.

### Service Deployment

1. **Create a Docker Compose File for Swarm**

   Create a `docker-compose.swarm.yml` file:

   ```yaml
   version: '3.8'

   services:
     freeradius:
       image: ${REGISTRY}/freeradius-totp:latest
       deploy:
         replicas: 2
         update_config:
           parallelism: 1
           delay: 10s
           order: start-first
         restart_policy:
           condition: any
           delay: 5s
           max_attempts: 3
         resources:
           limits:
             cpus: '0.5'
             memory: 512M
       ports:
         - "1812:1812/udp"
         - "1813:1813/udp"
       volumes:
         - radius-config:/etc/raddb
         - radius-data:/data/sqlite
       environment:
         - TZ=UTC
         - SQLITE_DB=/data/sqlite/radius.db
       networks:
         - radius-network
       healthcheck:
         test: ["CMD", "/usr/local/bin/healthcheck.sh"]
         interval: 30s
         timeout: 10s
         retries: 3
         start_period: 15s

     webui:
       image: ${REGISTRY}/radius-webui:latest
       deploy:
         replicas: 2
         update_config:
           parallelism: 1
           delay: 10s
           order: start-first
         restart_policy:
           condition: any
           delay: 5s
           max_attempts: 3
         resources:
           limits:
             cpus: '0.5'
             memory: 512M
       ports:
         - "8080:8080"
       volumes:
         - radius-data:/data/sqlite
         - radius-backups:/data/backups
       environment:
         - TZ=UTC
         - SQLITE_DB=/data/sqlite/radius.db
         - ADMIN_USER=admin
         - ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
         - USE_SSL=${USE_SSL:-false}
         - SSL_CERT=/app/ssl/server.crt
         - SSL_KEY=/app/ssl/server.key
         - BACKUP_DIR=/data/backups
       networks:
         - radius-network
       healthcheck:
         test: ["CMD", "/usr/local/bin/healthcheck.sh"]
         interval: 30s
         timeout: 10s
         retries: 3
         start_period: 15s

   volumes:
     radius-config:
       driver: local
     radius-data:
       driver: local
     radius-backups:
       driver: local

   networks:
     radius-network:
       driver: overlay
   ```

2. **Build and Push the Images**

   ```bash
   # Set the registry variable
   export REGISTRY=your-registry.com

   # Build the images
   docker-compose build

   # Push the images to the registry
   docker-compose push
   ```

3. **Deploy the Stack**

   ```bash
   docker stack deploy -c docker-compose.swarm.yml radius-totp
   ```

4. **Verify the Deployment**

   ```bash
   docker stack services radius-totp
   ```

   Ensure all services are running with the expected number of replicas.

### Scaling Services

To scale services in a Docker Swarm deployment:

```bash
# Scale the WebUI service to 3 replicas
docker service scale radius-totp_webui=3

# Scale the FreeRADIUS service to 3 replicas
docker service scale radius-totp_freeradius=3
```

### Rolling Updates

To perform a rolling update in a Docker Swarm deployment:

1. **Update the Images**

   ```bash
   # Build and push the new images
   docker-compose build
   docker-compose push
   ```

2. **Update the Services**

   ```bash
   # Update the stack
   docker stack deploy -c docker-compose.swarm.yml radius-totp
   ```

   Docker Swarm will perform a rolling update according to the `update_config` settings.

3. **Monitor the Update**

   ```bash
   docker service ls
   ```

   Ensure all services are updated and running.

## Security Hardening

### Network Security

1. **Firewall Configuration**

   Configure a firewall to restrict access to only the necessary ports:

   ```bash
   # Allow SSH
   ufw allow 22/tcp

   # Allow RADIUS authentication and accounting
   ufw allow 1812/udp
   ufw allow 1813/udp

   # Allow Web UI (if not behind a reverse proxy)
   ufw allow 8080/tcp

   # Allow HTTPS (if using a reverse proxy)
   ufw allow 443/tcp

   # Enable the firewall
   ufw enable
   ```

2. **Network Segmentation**

   Place the system in a separate network segment with restricted access.

3. **VPN Access**

   Consider requiring VPN access for administrative functions.

### Container Security

1. **Non-Root User**

   Ensure containers run as non-root users:

   ```yaml
   user: 1000:1000
   ```

2. **Read-Only Filesystem**

   Mount filesystems as read-only where possible:

   ```yaml
   volumes:
     - type: bind
       source: ./config
       target: /etc/raddb
       read_only: true
   ```

3. **Resource Limits**

   Set resource limits to prevent resource exhaustion:

   ```yaml
   deploy:
     resources:
       limits:
         cpus: '0.5'
         memory: 512M
   ```

4. **Security Profiles**

   Use security profiles to restrict container capabilities:

   ```yaml
   security_opt:
     - no-new-privileges:true
     - seccomp:/path/to/seccomp/profile.json
   ```

### Authentication Security

1. **Strong Passwords**

   Enforce strong password policies:
   - Minimum length: 12 characters
   - Require uppercase and lowercase letters, numbers, and special characters
   - Regular password rotation

2. **Two-Factor Authentication**

   Enable TOTP for all administrative users.

3. **API Security**

   Secure API access:
   - Use API keys with limited permissions
   - Implement rate limiting
   - Validate all input

4. **Session Security**

   Secure user sessions:
   - Set appropriate session timeouts
   - Use secure cookies
   - Implement CSRF protection

### SSL/TLS Configuration

1. **Certificate Management**

   Use certificates from a trusted CA for production:

   ```bash
   # Install certbot for Let's Encrypt certificates
   apt-get install -y certbot

   # Obtain a certificate
   certbot certonly --standalone -d your-domain.com

   # Copy the certificates to the appropriate location
   cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /path/to/server.crt
   cp /etc/letsencrypt/live/your-domain.com/privkey.pem /path/to/server.key
   ```

2. **Strong Cipher Suites**

   Configure strong cipher suites:

   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_prefer_server_ciphers on;
   ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
   ```

3. **HSTS**

   Implement HTTP Strict Transport Security:

   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```

## Monitoring and Logging

### Container Monitoring

1. **Docker Stats**

   Basic monitoring using Docker stats:

   ```bash
   docker stats
   ```

2. **Prometheus and Grafana**

   Set up Prometheus and Grafana for advanced monitoring:

   ```yaml
   # docker-compose.monitoring.yml
   version: '3.8'

   services:
     prometheus:
       image: prom/prometheus
       volumes:
         - ./prometheus.yml:/etc/prometheus/prometheus.yml
       ports:
         - "9090:9090"

     grafana:
       image: grafana/grafana
       ports:
         - "3000:3000"
       depends_on:
         - prometheus
   ```

3. **Node Exporter**

   Monitor host metrics using Node Exporter:

   ```yaml
   node-exporter:
     image: prom/node-exporter
     volumes:
       - /proc:/host/proc:ro
       - /sys:/host/sys:ro
       - /:/rootfs:ro
     command:
       - '--path.procfs=/host/proc'
       - '--path.sysfs=/host/sys'
       - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'
     ports:
       - "9100:9100"
   ```

### Log Management

1. **Centralized Logging**

   Set up centralized logging using Fluentd, Elasticsearch, and Kibana:

   ```yaml
   # docker-compose.logging.yml
   version: '3.8'

   services:
     fluentd:
       image: fluent/fluentd
       volumes:
         - ./fluentd/conf:/fluentd/etc
       ports:
         - "24224:24224"
         - "24224:24224/udp"

     elasticsearch:
       image: docker.elastic.co/elasticsearch/elasticsearch:7.10.0
       environment:
         - discovery.type=single-node
       ports:
         - "9200:9200"

     kibana:
       image: docker.elastic.co/kibana/kibana:7.10.0
       ports:
         - "5601:5601"
       depends_on:
         - elasticsearch
   ```

2. **Log Rotation**

   Configure log rotation to manage log file sizes:

   ```bash
   # /etc/logrotate.d/docker
   /var/lib/docker/containers/*/*.log {
       rotate 7
       daily
       compress
       missingok
       delaycompress
       copytruncate
   }
   ```

### Health Checks

1. **Container Health Checks**

   Configure health checks in Docker Compose:

   ```yaml
   healthcheck:
     test: ["CMD", "/usr/local/bin/healthcheck.sh"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 15s
   ```

2. **External Health Checks**

   Set up external health checks using a monitoring service:

   ```bash
   # Check if the Web UI is accessible
   curl -f http://localhost:8080/api/health || echo "Web UI is down"

   # Check if RADIUS is responding
   echo "User-Name=healthcheck" | radclient -t 2 localhost:1812 auth testing123 || echo "RADIUS is down"
   ```

### Alerting

1. **Email Alerts**

   Configure email alerts for critical issues:

   ```yaml
   # alertmanager.yml
   global:
     smtp_smarthost: 'smtp.example.com:587'
     smtp_from: 'alertmanager@example.com'
     smtp_auth_username: 'alertmanager'
     smtp_auth_password: 'password'

   route:
     group_by: ['alertname', 'instance']
     group_wait: 30s
     group_interval: 5m
     repeat_interval: 3h
     receiver: 'email'

   receivers:
   - name: 'email'
     email_configs:
     - to: 'admin@example.com'
   ```

2. **Slack Alerts**

   Configure Slack alerts for team notifications:

   ```yaml
   receivers:
   - name: 'slack'
     slack_configs:
     - api_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
       channel: '#alerts'
       text: '{{ template "slack.default.text" . }}'
   ```

## Backup and Recovery

### Backup Strategy

1. **Database Backups**

   Configure regular database backups:

   ```bash
   # Create a backup script
   cat > /usr/local/bin/backup-radius.sh << EOF
   #!/bin/bash
   TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
   BACKUP_DIR=/path/to/backups
   mkdir -p \$BACKUP_DIR

   # Backup the SQLite database
   docker-compose exec -T webui sqlite3 /data/sqlite/radius.db .dump > \$BACKUP_DIR/radius_db_\$TIMESTAMP.sql

   # Backup configuration files
   docker-compose exec -T freeradius tar -czf - /etc/raddb > \$BACKUP_DIR/raddb_config_\$TIMESTAMP.tar.gz

   # Rotate backups (keep last 7 days)
   find \$BACKUP_DIR -name "radius_db_*.sql" -type f -mtime +7 -delete
   find \$BACKUP_DIR -name "raddb_config_*.tar.gz" -type f -mtime +7 -delete
   EOF

   chmod +x /usr/local/bin/backup-radius.sh
   ```

   Add a cron job to run the script daily:

   ```bash
   echo "0 2 * * * /usr/local/bin/backup-radius.sh >> /var/log/radius-backup.log 2>&1" | crontab -
   ```

2. **Off-site Backups**

   Configure off-site backups for disaster recovery:

   ```bash
   # Add to the backup script
   cat >> /usr/local/bin/backup-radius.sh << EOF
   # Copy backups to off-site storage
   rsync -avz \$BACKUP_DIR/ user@remote-server:/path/to/backup/storage/
   EOF
   ```

### Recovery Procedures

1. **Database Recovery**

   Restore the database from a backup:

   ```bash
   # Stop the containers
   docker-compose down

   # Restore the database
   cat /path/to/backups/radius_db_20250416_020000.sql | docker-compose exec -T webui sqlite3 /data/sqlite/radius.db

   # Start the containers
   docker-compose up -d
   ```

2. **Configuration Recovery**

   Restore configuration files from a backup:

   ```bash
   # Extract the configuration backup
   mkdir -p /tmp/raddb-restore
   tar -xzf /path/to/backups/raddb_config_20250416_020000.tar.gz -C /tmp/raddb-restore

   # Copy the configuration files to the container
   docker cp /tmp/raddb-restore/etc/raddb/. freeradius-totp:/etc/raddb/

   # Restart the FreeRADIUS container
   docker-compose restart freeradius
   ```

3. **Full System Recovery**

   Recover the entire system:

   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/freeradius-totp-management.git
   cd freeradius-totp-management

   # Restore configuration files
   mkdir -p data/radius
   tar -xzf /path/to/backups/raddb_config_20250416_020000.tar.gz -C /tmp/raddb-restore
   cp -r /tmp/raddb-restore/etc/raddb/. data/radius/

   # Start the containers
   docker-compose up -d

   # Restore the database
   cat /path/to/backups/radius_db_20250416_020000.sql | docker-compose exec -T webui sqlite3 /data/sqlite/radius.db

   # Restart the containers
   docker-compose restart
   ```

## Scaling Guidelines

### Vertical Scaling

Increase resources for existing containers:

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 4G
```

### Horizontal Scaling

Add more replicas in a Docker Swarm deployment:

```bash
docker service scale radius-totp_webui=3
```

### Database Scaling

For high-volume deployments, consider migrating from SQLite to a more scalable database:

1. **PostgreSQL Migration**

   Update the FreeRADIUS SQL configuration to use PostgreSQL:

   ```
   # /etc/raddb/mods-available/sql
   sql {
     driver = "rlm_sql_postgresql"
     dialect = "postgresql"
     server = "postgres"
     port = 5432
     login = "radius"
     password = "radpass"
     radius_db = "radius"
   }
   ```

2. **Connection Pooling**

   Implement connection pooling for better performance:

   ```
   # /etc/raddb/mods-available/sql
   sql {
     pool {
       start = 5
       min = 5
       max = 20
       spare = 5
       uses = 0
       lifetime = 0
       idle_timeout = 60
     }
   }
   ```

## Upgrade Procedures

### Planning an Upgrade

1. **Review Changes**

   Review the changes in the new version:

   ```bash
   git fetch
   git log --oneline HEAD..origin/main
   ```

2. **Backup Current System**

   Create a backup before upgrading:

   ```bash
   ./backup-radius.sh
   ```

3. **Test in a Staging Environment**

   Test the upgrade in a staging environment before applying to production.

### Performing the Upgrade

1. **Pull the Latest Changes**

   ```bash
   git pull origin main
   ```

2. **Update the Containers**

   ```bash
   # For Docker Compose
   docker-compose down
   docker-compose up -d --build

   # For Docker Swarm
   docker stack deploy -c docker-compose.swarm.yml radius-totp
   ```

3. **Verify the Upgrade**

   ```bash
   # Check container status
   docker-compose ps

   # Check logs for errors
   docker-compose logs

   # Test functionality
   curl -f http://localhost:8080/api/health
   ```

### Rollback Procedures

If the upgrade fails, roll back to the previous version:

1. **Revert to Previous Version**

   ```bash
   git checkout <previous-commit>
   ```

2. **Restore from Backup**

   ```bash
   # Restore database
   cat /path/to/backups/radius_db_pre_upgrade.sql | docker-compose exec -T webui sqlite3 /data/sqlite/radius.db

   # Restore configuration
   tar -xzf /path/to/backups/raddb_config_pre_upgrade.tar.gz -C /tmp/raddb-restore
   docker cp /tmp/raddb-restore/etc/raddb/. freeradius-totp:/etc/raddb/
   ```

3. **Restart the Containers**

   ```bash
   docker-compose down
   docker-compose up -d
   ```

4. **Verify the Rollback**

   ```bash
   # Check container status
   docker-compose ps

   # Test functionality
   curl -f http://localhost:8080/api/health