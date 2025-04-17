FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ /app/
COPY scripts/ /app/scripts/

# Make scripts executable
RUN chmod +x /app/scripts/*.sh || true

# Create a startup script
RUN echo '#!/bin/bash\n\
# Wait for FreeRADIUS to be ready\n\
echo "Waiting for FreeRADIUS to be ready..."\n\
sleep 5\n\
\n\
# Start the Flask application\n\
exec python /app/app.py\n\
' > /app/scripts/start.sh && chmod +x /app/scripts/start.sh

# Expose the web UI port
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/scripts/start.sh"]