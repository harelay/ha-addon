#!/usr/bin/with-contenv bashio
# HARelay Tunnel App Entry Point

bashio::log.info "Starting HARelay..."

# Run the Python app
exec python3 /app/run.py
