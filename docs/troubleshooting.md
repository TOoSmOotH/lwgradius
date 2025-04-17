# Troubleshooting Guide

This guide provides solutions for common issues you might encounter with the FreeRADIUS TOTP Management System.

## Table of Contents

- [General Troubleshooting Process](#general-troubleshooting-process)
- [Docker and Container Issues](#docker-and-container-issues)
- [FreeRADIUS Issues](#freeradius-issues)
- [Web UI Issues](#web-ui-issues)
- [Database Issues](#database-issues)
- [API Issues](#api-issues)
- [Backup and Restore Issues](#backup-and-restore-issues)
- [Common Error Messages](#common-error-messages)
- [Getting Help](#getting-help)

## General Troubleshooting Process

When troubleshooting issues with the FreeRADIUS TOTP Management System, follow these general steps:

1. **Identify the Problem**
   - What component is affected? (FreeRADIUS, Web UI, Database)
   - What are the symptoms? (Error messages, unexpected behavior)
   - When did the problem start? (After an update, configuration change)

2. **Check Logs**
   - Docker container logs: `docker-compose logs`
   - FreeRADIUS logs: `docker-compose exec freeradius tail -f /var/log/freeradius/radius.log`
   - Web UI logs: `docker-compose logs webui`

3. **Verify Configuration**
   - Docker Compose configuration: `docker-compose config`
   - FreeRADIUS configuration: `docker-compose exec freeradius radiusd -XC`
   - Web UI configuration: Check environment variables

4. **Check System Resources**
   - CPU and memory usage: `docker stats`
   - Disk space: `df -h`
   - Network connectivity: `netstat -tuln`

5. **Isolate the Issue**
   - Test components individually
   - Reproduce the issue in a controlled environment

## Docker and Container Issues

### Containers Won't Start

**Symptoms:**
- Containers fail to start
- `docker-compose up` command fails

**Solutions:**

1. **Check for port conflicts:**
   ```bash
   netstat -tuln | grep 1812
   netstat -tuln | grep 8080
   ```

2. **Verify volume mounts:**
   ```bash
   docker volume ls
   docker volume inspect radius-data
   ```

3. **Check Docker Compose configuration:**
   ```bash
   docker-compose config
   ```

4. **Review container logs:**
   ```bash
   docker-compose logs freeradius
   docker-compose logs webui
   ```

### Container Health Check Failures

**Symptoms:**
- Containers marked as unhealthy
- Containers restart due to failed health checks

**Solutions:**

1. **Test health check manually:**
   ```bash
   docker-compose exec freeradius /usr/local/bin/healthcheck.sh
   docker-compose exec webui /usr/local/bin/healthcheck.sh
   ```

2. **Adjust health check parameters in docker-compose.yml:**
   ```yaml
   healthcheck:
     test: ["CMD", "/usr/local/bin/healthcheck.sh"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 15s
   ```

3. **Check application logs:**
   ```bash
   docker-compose exec freeradius tail -f /var/log/freeradius/radius.log
   ```

## FreeRADIUS Issues

### Authentication Failures

**Symptoms:**
- Users can't authenticate
- Authentication failures in logs

**Solutions:**

1. **Check user credentials:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "SELECT * FROM radcheck WHERE username='testuser';"
   ```

2. **Test authentication manually:**
   ```bash
   docker-compose exec freeradius radtest testuser password localhost 0 testing123
   ```

3. **Check FreeRADIUS configuration:**
   ```bash
   docker-compose exec freeradius radiusd -XC
   ```

4. **Run FreeRADIUS in debug mode:**
   ```bash
   docker-compose stop freeradius
   docker-compose run --rm freeradius radiusd -X
   ```

### TOTP Verification Problems

**Symptoms:**
- TOTP tokens not accepted
- Time synchronization issues

**Solutions:**

1. **Check time synchronization:**
   ```bash
   docker-compose exec freeradius date
   date
   ```

2. **Verify TOTP secret:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "SELECT * FROM radcheck WHERE attribute='TOTP-Secret' AND username='testuser';"
   ```

3. **Test TOTP verification manually:**
   ```bash
   # Generate TOTP code
   docker-compose exec webui python -c "import pyotp; print(pyotp.TOTP('JBSWY3DPEHPK3PXP').now())"
   
   # Test authentication with TOTP
   docker-compose exec freeradius radtest testuser "password123456" localhost 0 testing123
   ```

4. **Adjust time window for TOTP verification:**
   ```
   # In /etc/raddb/mods-available/totp
   totp {
     time_step = 30
     window = 2  # Increase window for more tolerance
   }
   ```

## Web UI Issues

### Web UI Not Accessible

**Symptoms:**
- Web UI doesn't load in browser
- Connection refused or timeout errors

**Solutions:**

1. **Check container status:**
   ```bash
   docker-compose ps webui
   ```

2. **Check container logs:**
   ```bash
   docker-compose logs webui
   ```

3. **Test network connectivity:**
   ```bash
   nc -zv localhost 8080
   ```

4. **Restart the Web UI container:**
   ```bash
   docker-compose restart webui
   ```

### Login Problems

**Symptoms:**
- Can't log in to the Web UI
- Invalid credentials errors

**Solutions:**

1. **Check admin user in database:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "SELECT * FROM admin_users WHERE username='admin';"
   ```

2. **Reset admin password:**
   ```bash
   # Generate password hash
   docker-compose exec webui python -c "import bcrypt; print(bcrypt.hashpw('newpassword'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))"
   
   # Update password in database
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "UPDATE admin_users SET password_hash='generated_hash' WHERE username='admin';"
   ```

3. **Clear browser cookies and cache**

### SSL/TLS Issues

**Symptoms:**
- SSL certificate errors
- HTTPS not working

**Solutions:**

1. **Check SSL configuration:**
   ```bash
   docker-compose exec webui cat /app/app.py | grep SSL
   ```

2. **Verify certificate files:**
   ```bash
   docker-compose exec webui ls -la /app/ssl/
   ```

3. **Generate new self-signed certificates:**
   ```bash
   ./certs/generate-certs.sh
   ```

## Database Issues

### Database Connection Failures

**Symptoms:**
- "Database not found" errors
- Connection timeout errors

**Solutions:**

1. **Check database file:**
   ```bash
   docker-compose exec webui ls -la /data/sqlite/radius.db
   ```

2. **Check database path configuration:**
   ```bash
   docker-compose exec webui env | grep SQLITE_DB
   ```

3. **Check file permissions:**
   ```bash
   docker-compose exec webui ls -la /data/sqlite/
   
   # Fix permissions
   docker-compose exec webui chmod 644 /data/sqlite/radius.db
   ```

4. **Recreate database if necessary:**
   ```bash
   # Backup existing database
   docker-compose exec webui sqlite3 /data/sqlite/radius.db .dump > /tmp/radius_backup.sql
   
   # Create new database
   docker-compose exec webui sqlite3 /data/sqlite/radius.db < /etc/raddb/mods-config/sql/sqlite/schema.sql
   ```

### Database Corruption

**Symptoms:**
- SQLite error messages
- "database disk image is malformed" errors

**Solutions:**

1. **Check database integrity:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "PRAGMA integrity_check;"
   ```

2. **Recover database:**
   ```bash
   # Dump recoverable data
   docker-compose exec webui sqlite3 /data/sqlite/radius.db ".recover" > /tmp/recovered.sql
   
   # Create new database
   docker-compose exec webui sqlite3 /data/sqlite/radius_new.db < /tmp/recovered.sql
   
   # Replace corrupted database
   docker-compose exec webui mv /data/sqlite/radius_new.db /data/sqlite/radius.db
   ```

3. **Restore from backup:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db < /path/to/backup.sql
   ```

## API Issues

### API Authentication Problems

**Symptoms:**
- "Unauthorized" errors from API
- API key not accepted

**Solutions:**

1. **Verify API key:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "SELECT * FROM api_keys WHERE key='your-api-key';"
   ```

2. **Test API authentication:**
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:8080/api/users
   ```

3. **Generate new API key:**
   ```bash
   # Generate new API key
   docker-compose exec webui python -c "import secrets; print(secrets.token_hex(16))"
   
   # Add new API key to database
   docker-compose exec webui sqlite3 /data/sqlite/radius.db "INSERT INTO api_keys (key, name, created_by) VALUES ('new-api-key', 'Test Key', 'admin');"
   ```

### API Rate Limiting

**Symptoms:**
- "Too many requests" errors
- HTTP 429 status codes

**Solutions:**

1. **Check rate limit headers:**
   ```bash
   curl -v -H "X-API-Key: your-api-key" http://localhost:8080/api/users | grep -i "ratelimit"
   ```

2. **Implement client-side rate limiting with backoff**

3. **Use multiple API keys for different services**

## Backup and Restore Issues

### Backup Creation Failures

**Symptoms:**
- Backup process fails
- Incomplete backups

**Solutions:**

1. **Check disk space:**
   ```bash
   docker-compose exec webui df -h
   ```

2. **Check backup directory:**
   ```bash
   docker-compose exec webui ls -la /data/backups
   
   # Create backup directory if missing
   docker-compose exec webui mkdir -p /data/backups
   ```

3. **Test backup process manually:**
   ```bash
   docker-compose exec webui sqlite3 /data/sqlite/radius.db .dump > /tmp/manual_backup.sql
   ```

### Restore Failures

**Symptoms:**
- Restore process fails
- Incomplete restoration

**Solutions:**

1. **Verify backup file:**
   ```bash
   docker-compose exec webui head -n 20 /data/backups/radius_backup.sql
   ```

2. **Test restore to temporary database:**
   ```bash
   docker-compose exec webui sqlite3 /tmp/test_restore.db < /data/backups/radius_backup.sql
   ```

3. **Stop services before restore:**
   ```bash
   # Stop services
   docker-compose stop
   
   # Restore database
   docker-compose run --rm webui sqlite3 /data/sqlite/radius.db < /data/backups/radius_backup.sql
   
   # Start services
   docker-compose up -d
   ```

## Common Error Messages

### FreeRADIUS Error Messages

- **"Failed to find client"**: Check clients.conf and verify client IP address
- **"Failed to load module"**: Check module configuration and dependencies
- **"Invalid username or password"**: Verify user credentials in database
- **"Failed to connect to database"**: Check database connection configuration

### Web UI Error Messages

- **"Database not found"**: Verify database path and file existence
- **"Invalid credentials"**: Check admin username and password
- **"Internal server error"**: Check application logs for details
- **"SSL certificate error"**: Verify SSL certificate configuration

### Docker Error Messages

- **"Port is already allocated"**: Check for port conflicts
- **"No such file or directory"**: Verify volume mounts and file paths
- **"Container exited with code 1"**: Check container logs for error details
- **"Unhealthy container"**: Check health check configuration and logs

## Getting Help

If you encounter issues not covered in this guide:

1. **Check the logs** for detailed error messages
2. **Search the documentation** for similar issues
3. **Check the GitHub repository** for known issues and solutions
4. **Contact the system administrator** for assistance

For critical issues, provide the following information:
- Detailed description of the problem
- Steps to reproduce the issue
- Error messages and logs
- System information (Docker version, OS, etc.)
