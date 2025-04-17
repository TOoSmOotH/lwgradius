#!/bin/bash
set -e

# Create necessary directories
mkdir -p /etc/freeradius/3.0/mods-enabled
mkdir -p /etc/freeradius/3.0/sites-enabled
mkdir -p /data/sqlite

# Create symbolic links for modules and sites if they don't exist
echo "Setting up FreeRADIUS configuration..."

# Enable SQL module
if [ ! -L /etc/freeradius/3.0/mods-enabled/sql ]; then
    ln -sf /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-enabled/
    echo "Enabled SQL module"
fi

# Enable TOTP module
if [ ! -L /etc/freeradius/3.0/mods-enabled/totp ]; then
    ln -sf /etc/freeradius/3.0/mods-available/totp /etc/freeradius/3.0/mods-enabled/
    echo "Enabled TOTP module"
fi

# Enable default site
if [ ! -L /etc/freeradius/3.0/sites-enabled/default ]; then
    ln -sf /etc/freeradius/3.0/sites-available/default /etc/freeradius/3.0/sites-enabled/
    echo "Enabled default site"
fi

# Initialize SQLite database if it doesn't exist
if [ ! -f "$SQLITE_DB" ]; then
    echo "Initializing SQLite database at $SQLITE_DB..."
    mkdir -p $(dirname "$SQLITE_DB")
    sqlite3 "$SQLITE_DB" < /etc/freeradius/3.0/mods-config/sql/sqlite/schema.sql
    echo "Database initialized successfully"
    
    # Set proper permissions
    chown -R freerad:freerad $(dirname "$SQLITE_DB")
    chmod -R 755 $(dirname "$SQLITE_DB")
fi

# Ensure proper permissions on the database file
chown freerad:freerad "$SQLITE_DB"
chmod 644 "$SQLITE_DB"

# Set proper permissions for FreeRADIUS configuration
chown -R freerad:freerad /etc/freeradius/3.0
chmod -R 755 /etc/freeradius/3.0

echo "Starting FreeRADIUS server..."
# Start FreeRADIUS in debug mode
exec /usr/sbin/freeradius -X