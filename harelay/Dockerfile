ARG BUILD_FROM
FROM $BUILD_FROM

# Install Python and required packages
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-aiohttp \
    py3-websockets \
    py3-msgpack

# Copy application
COPY rootfs /
COPY run.py /app/run.py
COPY templates /app/templates

# Set working directory
WORKDIR /app

# Make scripts executable
RUN chmod a+x /run.sh

# Expose ingress port
EXPOSE 8099

# Run the add-on
CMD [ "/run.sh" ]
