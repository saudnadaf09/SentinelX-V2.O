# Single-container build for hosting (Render etc.): builds the React UI, then serves UI + API from one process.
FROM node:20-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app/backend
COPY backend/requirements-lite.txt ./
RUN pip install -r requirements-lite.txt
COPY backend/ ./
COPY detection-rules /app/detection-rules
COPY --from=web /web/dist /app/frontend/dist
RUN useradd --system --uid 10001 --no-create-home sentinelx && mkdir -p /app/backend/data && chown -R sentinelx /app
USER sentinelx
ENV APP_ENV=production QUEUE_BACKEND=memory STORE_BACKEND=sqlite \
    DATABASE_URL=sqlite:///./data/sentinelx.db EVENTS_DB_PATH=./data/events.db \
    FRONTEND_DIST=/app/frontend/dist RULES_DIR=/app/detection-rules AI_PROVIDER=disabled
EXPOSE 10000
CMD ["python", "deploy_start.py"]
