#!/bin/bash
set -e

echo "Starting RADIUS TOTP Management Web UI..."

# Wait for FreeRADIUS to be ready
echo "Waiting for FreeRADIUS to be ready..."
sleep 5

# Check if the database exists
if [ ! -f "$SQLITE_DB" ]; then
    echo "Error: SQLite database not found at $SQLITE_DB"
    echo "Please ensure the FreeRADIUS container has initialized the database"
    exit 1
fi

# Set proper permissions for the database
chmod 644 "$SQLITE_DB"

# Create admin user if not exists
echo "Checking admin user..."
ADMIN_EXISTS=$(sqlite3 "$SQLITE_DB" "SELECT COUNT(*) FROM admin_users WHERE username='$ADMIN_USER';")

if [ "$ADMIN_EXISTS" -eq "0" ]; then
    echo "Creating admin user..."
    sqlite3 "$SQLITE_DB" "INSERT INTO admin_users (username, password_hash, role) VALUES ('$ADMIN_USER', '$ADMIN_PASSWORD_HASH', 'admin');"
    echo "Admin user created successfully"
fi

# Start the Flask application
echo "Starting Flask application..."
cd /app
exec gunicorn --bind 0.0.0.0:8080 --workers 2 --threads 2 app:app