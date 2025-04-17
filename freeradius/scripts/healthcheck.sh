#!/bin/bash
set -e

# Health check script for FreeRADIUS server
# This script checks if the FreeRADIUS server is responding to authentication requests

# Configuration
RADIUS_HOST="localhost"
RADIUS_PORT="1812"
RADIUS_SECRET="testing123"
TEST_USER="healthcheck"
TEST_PASSWORD="healthcheck"

# Check if radclient is available
if ! command -v radclient &> /dev/null; then
    echo "Error: radclient command not found"
    exit 1
fi

# Create a temporary file for the radclient request
TEMP_FILE=$(mktemp)
cat > "${TEMP_FILE}" << EOF
User-Name = "${TEST_USER}"
User-Password = "${TEST_PASSWORD}"
EOF

# Send a test authentication request to the FreeRADIUS server
# We don't care if authentication succeeds, just that the server responds
if radclient -t 2 -r 1 -f "${TEMP_FILE}" "${RADIUS_HOST}:${RADIUS_PORT}" auth "${RADIUS_SECRET}" &> /dev/null; then
    # Server responded (success or failure doesn't matter for health check)
    rm "${TEMP_FILE}"
    exit 0
else
    # Server did not respond
    rm "${TEMP_FILE}"
    echo "Error: FreeRADIUS server is not responding"
    exit 1
fi