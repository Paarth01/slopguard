FROM python:3.11-slim

# Install any system deps here
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy action code into container (adjust paths to your repo)
COPY entrypoint.sh /entrypoint.sh
COPY src/ /app/src/

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
