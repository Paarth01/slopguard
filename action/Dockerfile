# Dedicated image for the GitHub Action. Kept separate from the root
# Dockerfile (which serves the FastAPI app) since the Action needs a
# different entrypoint and doesn't need uvicorn at all.
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY slopguard ./slopguard
COPY action ./action
COPY templates ./templates
COPY README.md .

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["sh", "/app/action/entrypoint.sh"]
