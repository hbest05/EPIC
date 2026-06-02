# Backend Dockerfile — FastAPI + Uvicorn
#
# Build context: repo root (set in docker-compose.yml as context: .)
# so that both backend/ and blockchain/MessageDigestRegistryABI.json
# are reachable from COPY instructions.

FROM python:3.12-slim AS base

WORKDIR /app

# System dependencies:
#   gcc, libpq-dev — required by argon2-cffi and asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies before copying source so Docker layer-caches
# the pip install step as long as requirements.txt hasn't changed.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source into /app
COPY backend/ .

# Copy the contract ABI into /abi/ — a path OUTSIDE /app so the dev hot-reload
# volume mount (./backend:/app) does not shadow it at runtime.
# blockchain_service.py checks /abi/MessageDigestRegistryABI.json first.
COPY blockchain/MessageDigestRegistryABI.json /abi/MessageDigestRegistryABI.json

COPY frontend/ /app/frontend/
COPY public/   /app/public/

# Run as a non-root user — if an RCE occurs the attacker does not get UID 0.
RUN useradd -u 1001 -m appuser \
    && chown -R appuser /app /abi
USER 1001

# Run Alembic migrations then start Uvicorn.
# TODO: In production use gunicorn with uvicorn workers for multiple processes.
# Set APP_ENV=development to enable hot-reload (docker-compose does this automatically).
CMD ["sh", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000 ${APP_ENV:+--reload}"]
