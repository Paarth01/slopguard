FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY slopguard ./slopguard
COPY action ./action
COPY templates ./templates
COPY README.md .

RUN pip install --no-cache-dir -e .

COPY action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
