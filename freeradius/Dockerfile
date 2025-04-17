FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install FreeRADIUS with SQLite support and other dependencies
RUN apt-get update && apt-get install -y \
    freeradius \
    freeradius-utils \
    sqlite3 \
    libqrencode4 \
    libpam-google-authenticator \
    openssl \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directory for SQLite database
RUN mkdir -p /data/sqlite

# Copy configuration files
COPY config/ /etc/freeradius/3.0/
COPY scripts/ /usr/local/bin/

# Make scripts executable
RUN chmod +x /usr/local/bin/*.sh || true

# Create a startup script
RUN echo '#!/bin/bash\n\
# Initialize database if it doesn\'t exist\n\
if [ ! -f "$SQLITE_DB" ]; then\n\
    echo "Initializing SQLite database..."\n\
    sqlite3 "$SQLITE_DB" < /etc/freeradius/3.0/mods-config/sql/sqlite/schema.sql\n\
fi\n\
\n\
# Start FreeRADIUS in debug mode\n\
exec /usr/sbin/freeradius -X\n\
' > /usr/local/bin/start.sh && chmod +x /usr/local/bin/start.sh

# Expose standard RADIUS ports
EXPOSE 1812/udp 1813/udp

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/start.sh"]