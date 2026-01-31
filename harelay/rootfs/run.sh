#!/usr/bin/with-contenv bashio
# HARelay Tunnel Add-on Entry Point

bashio::log.info "Starting HARelay..."

# Run the Python add-on
exec python3 /app/run.py
