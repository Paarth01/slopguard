FROM python:3.11-slim

WORKDIR /app

# Copy files from parent directories using ../
COPY ../pyproject.toml ../requirements.txt ./
COPY ../slopguard ./slopguard
COPY . ./action
COPY ../templates ./templates
COPY ../README.md .

RUN pip install --no-cache-dir -e .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
