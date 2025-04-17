#!/bin/bash
set -e

# Health check script for the WebUI container
# This script checks if the Flask application is responding to HTTP requests

# Configuration
WEBUI_HOST="localhost"
WEBUI_PORT="8080"
HEALTH_ENDPOINT="/api/health"
TIMEOUT=5

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo "Error: curl command not found"
    exit 1
fi

# Send a request to the health check endpoint
response=$(curl -s -o /dev/null -w "%{http_code}" --max-time ${TIMEOUT} http://${WEBUI_HOST}:${WEBUI_PORT}${HEALTH_ENDPOINT})

if [ "$response" = "200" ]; then
    # Server responded with 200 OK
    exit 0
else
    # Server did not respond with 200 OK
    echo "Error: WebUI is not healthy (HTTP status: ${response})"
    exit 1
fi