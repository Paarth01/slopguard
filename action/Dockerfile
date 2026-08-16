FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY ../slopguard ./slopguard
COPY ../action ./action
COPY ../templates ./templates
COPY ../README.md .

RUN pip install --no-cache-dir -e .

EXPOSE 8000

# Uses shell form so $PORT expands -- Render (and most PaaS providers) set
# PORT at runtime and expect the app to bind to it; falls back to 8000 for
# local `docker compose up`.
CMD ["sh", "-c", "uvicorn slopguard.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
