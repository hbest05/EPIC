# Backend Dockerfile — FastAPI + Uvicorn
# Multi-stage build keeps the final image lean

FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies required by argon2-cffi and asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run Alembic migrations then start Uvicorn
# TODO: In production use gunicorn with uvicorn workers for multiple processes
CMD ["sh", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]
