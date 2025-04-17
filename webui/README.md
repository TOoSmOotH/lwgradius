# FreeRADIUS TOTP Management Web UI

This directory contains the web-based management interface for the FreeRADIUS TOTP Management System.

## Features

- **User Management**: Create, update, delete, and search RADIUS users
- **TOTP Token Management**: Generate and manage TOTP tokens for two-factor authentication
- **RADIUS Client Management**: Configure network devices that authenticate against the RADIUS server
- **Authentication Logs**: View and filter authentication success/failure logs
- **Audit Trail**: Track administrative actions for security and compliance
- **Admin User Management**: Control access to the management interface

## Technical Stack

- **Flask**: Python web framework
- **SQLite**: Database backend (shared with FreeRADIUS)
- **Bootstrap 5**: Frontend UI framework
- **Font Awesome**: Icon library
- **jQuery**: JavaScript library

## Directory Structure

```
webui/
├── app/
│   ├── static/          # Static assets (CSS, JS, images)
│   ├── templates/       # HTML templates
│   ├── app.py           # Main application file
│   ├── forms.py         # Form definitions
│   ├── models.py        # Database models
│   ├── routes.py        # Route definitions
│   └── utils.py         # Utility functions
├── scripts/             # Startup and maintenance scripts
├── Dockerfile           # Docker configuration
└── requirements.txt     # Python dependencies
```

## Configuration

The web UI is configured through environment variables:

- `SQLITE_DB`: Path to the SQLite database (default: `/data/sqlite/radius.db`)
- `SECRET_KEY`: Flask secret key for session security
- `ADMIN_USER`: Default admin username (default: `admin`)
- `ADMIN_PASSWORD_HASH`: Default admin password hash (default: `changeme`)
- `USE_SSL`: Enable SSL (default: `false`)
- `SSL_CERT`: Path to SSL certificate (when SSL is enabled)
- `SSL_KEY`: Path to SSL private key (when SSL is enabled)

## Development

To run the application in development mode:

```bash
cd webui
pip install -r requirements.txt
python -m app.app
```

The application will be available at http://localhost:8080.

## Docker Deployment

The web UI is designed to be deployed as part of the complete FreeRADIUS TOTP Management System using Docker Compose. See the main project README for deployment instructions.

## Security Considerations

- The web UI should be deployed behind a reverse proxy with HTTPS in production
- Admin passwords should be changed from the default
- Regular security updates should be applied
- Access to the management interface should be restricted to trusted networks

## License

This software is licensed under the same terms as the main FreeRADIUS TOTP Management System.