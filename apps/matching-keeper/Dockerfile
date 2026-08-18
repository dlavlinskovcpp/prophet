ARG PYTHON_BASE_IMAGE=python:3.11.14-slim-bookworm

FROM ${PYTHON_BASE_IMAGE} AS builder

ARG POETRY_VERSION=1.8.5

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

RUN python -m venv /opt/poetry \
    && /opt/poetry/bin/pip install "poetry==${POETRY_VERSION}"

ENV PATH="/opt/poetry/bin:${PATH}"

WORKDIR /app

# The keeper keeps prophet-sdk as a repository-relative path dependency.
COPY sdk/python/pyproject.toml sdk/python/poetry.lock /app/sdk/python/
COPY sdk/python/prophet_sdk/ /app/sdk/python/prophet_sdk/
COPY apps/matching-keeper/pyproject.toml apps/matching-keeper/poetry.lock /app/apps/matching-keeper/

WORKDIR /app/apps/matching-keeper
ENV PIP_DEFAULT_TIMEOUT=600 \
    PIP_READ_TIMEOUT=600 \
    POETRY_HTTP_TIMEOUT=600

RUN poetry env use /usr/local/bin/python \
    && poetry install --sync --only main --no-root --no-interaction --no-ansi


FROM ${PYTHON_BASE_IMAGE} AS runtime

ARG IMAGE_REVISION=unknown
ARG IMAGE_VERSION=dev
ARG IMAGE_SOURCE=https://github.com/dlavlinskovcpp/prophet

LABEL org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.source="${IMAGE_SOURCE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/apps/matching-keeper/.venv/bin:${PATH}" \
    PYTHONPATH="/app/apps/matching-keeper"

WORKDIR /app/apps/matching-keeper

COPY --from=builder /app/apps/matching-keeper/.venv /app/apps/matching-keeper/.venv
# prophet-sdk is an editable path dependency for the keeper, so retain exactly
# its expected repository-relative runtime path rather than duplicating it.
COPY sdk/python/prophet_sdk/ /app/sdk/python/prophet_sdk/
COPY apps/matching-keeper/src/ /app/apps/matching-keeper/src/

RUN mkdir -p /app/apps/matching-keeper/state

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=3).read()" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8010"]
