FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application source
COPY alembic.ini ./
COPY alembic/ ./alembic/
COPY src/ ./src/

# Re-install with source for the package to be importable
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "diagnose.main:app", "--host", "0.0.0.0", "--port", "8000"]
