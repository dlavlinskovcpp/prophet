FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

COPY sdk/python /app/sdk/python
COPY apps/matching-keeper /app/apps/matching-keeper

WORKDIR /app/apps/matching-keeper

RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi

RUN mkdir -p /app/apps/matching-keeper/state

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8010/health || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8010"]
