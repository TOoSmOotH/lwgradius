# FreeRADIUS TOTP Management System

## Project Overview

This project creates a comprehensive authentication system with the following components:

1. **FreeRADIUS Server** - For handling authentication requests
2. **TOTP Integration** - For two-factor authentication via Google Authenticator
3. **SQLite Database** - For storing user and configuration data
4. **Web UI** - For easy management of users, TOTP tokens, and RADIUS clients

## System Architecture

The system consists of multiple Docker containers working together:

1. **FreeRADIUS Container**: Core authentication server with TOTP module
2. **Web UI Container**: Flask-based web interface for administration
3. **Shared SQLite Database**: Volume-mounted database accessible by both containers

## Key Features

- **User Management**: Create, update, delete, and search users
- **TOTP Token Management**: Generate QR codes for Google Authenticator
- **RADIUS Client Management**: Configure network devices that will authenticate against the server
- **Authentication Logs**: View success/failure logs and analytics
- **API Access**: REST API for programmatic access
- **Multi-administrator Support**: Role-based access control for administrators

## Technical Components

### 1. Docker Compose Configuration

```yaml
version: '3'

services:
  freeradius:
    build:
      context: ./freeradius
      dockerfile: Dockerfile
    container_name: freeradius-totp
    restart: unless-stopped
    ports:
      - "1812:1812/udp"  # RADIUS authentication
      - "1813:1813/udp"  # RADIUS accounting
    volumes:
      - ./data/radius:/etc/raddb
      - ./data/sqlite:/data/sqlite
    environment:
      - TZ=UTC
      - SQLITE_DB=/data/sqlite/radius.db
    networks:
      - radius-network

  webui:
    build:
      context: ./webui
      dockerfile: Dockerfile
    container_name: radius-webui
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./data/sqlite:/data/sqlite
    environment:
      - TZ=UTC
      - SQLITE_DB=/data/sqlite/radius.db
      - ADMIN_USER=admin
      - ADMIN_PASSWORD_HASH=changeme
    networks:
      - radius-network
    depends_on:
      - freeradius

networks:
  radius-network:
    driver: bridge
```

### 2. FreeRADIUS Configuration

The FreeRADIUS server is configured to use SQLite for storing:
- User credentials
- TOTP secrets
- Client configurations
- Authentication logs

Key configuration files:
- `mods-available/sql` - Database connection configuration
- `mods-available/totp` - TOTP module settings
- `sites-available/default` - Authentication flow

### 3. Web UI Features

#### User Management

- **User List**: View all users with search and filter
- **User Creation**: Add new users with password or TOTP
- **User Edit**: Modify user properties and reset credentials
- **Batch Operations**: Import/export users

#### TOTP Management

- **Token Generation**: Create and display QR codes
- **Token Reset**: Revoke and regenerate tokens
- **Test Interface**: Verify TOTP codes work properly

#### Client Management

- **Network Devices**: Add/edit devices that will connect to RADIUS
- **Shared Secrets**: Manage and rotate shared secrets securely
- **IP Restrictions**: Configure allowed client IP addresses

#### System Logs & Monitoring

- **Authentication Logs**: View success/failure with filtering
- **System Status**: Monitor server health and performance
- **Audit Trail**: Track administrative actions

Should also use SSL

## Implementation Plan

### Phase 1: Core Infrastructure

1. Configure FreeRADIUS with SQLite support
2. Set up TOTP module integration
3. Create database schema
4. Establish basic Docker configuration

### Phase 2: Web UI Development

1. Develop Flask-based web application
2. Implement user management interfaces
3. Create TOTP configuration screens
4. Design client management system

### Phase 3: Integration & Testing

1. Connect Web UI to SQLite database
2. Implement API endpoints
3. Conduct security testing
4. Performance optimization

### Phase 4: Deployment & Documentation

1. Finalize Docker Compose configuration
2. Create comprehensive documentation
3. Add monitoring and backup tools
4. Prepare deployment guides

## Security Considerations

- HTTPS for Web UI access
- Strong password policies
- API authentication
- Database encryption
- Regular security updates
- Audit logging

## Directory Structure

```
/
├── data/
│   ├── radius/
│   └── sqlite/
├── freeradius/
│   ├── Dockerfile
│   ├── config/
│   │   ├── clients.conf
│   │   ├── radiusd.conf
│   │   ├── sites-available/
│   │   └── mods-available/
│   └── scripts/
├── webui/
│   ├── Dockerfile
│   ├── app/
│   │   ├── static/
│   │   ├── templates/
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── utils.py
│   └── scripts/
└── docker-compose.yml
```

## Conclusion

This project creates a comprehensive authentication solution combining the security of RADIUS with the convenience of TOTP authentication, all managed through an intuitive web interface. The system is designed to be easily deployable via Docker Compose, with sensible defaults but extensive configurability.