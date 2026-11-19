# Build context is the repository root (see docker-compose.yml)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY backend/ ./
COPY detection-rules /app/detection-rules
COPY sample-data /app/sample-data

RUN useradd --system --uid 10001 --no-create-home sentinelx && chown -R sentinelx /app
USER sentinelx

ENV RULES_DIR=/app/detection-rules SAMPLE_DATA_DIR=/app/sample-data
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && python -m app.cli bootstrap && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
