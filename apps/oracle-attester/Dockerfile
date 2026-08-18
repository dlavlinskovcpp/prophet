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

# Preserve the repository-relative path dependency:
# apps/oracle-attester -> ../../sdk/python.
COPY sdk/python/pyproject.toml sdk/python/poetry.lock /app/sdk/python/
COPY sdk/python/prophet_sdk/ /app/sdk/python/prophet_sdk/
COPY apps/oracle-attester/pyproject.toml apps/oracle-attester/poetry.lock /app/apps/oracle-attester/

WORKDIR /app/apps/oracle-attester

# Install exactly the committed lock contract. The service itself is source-run,
# so --no-root avoids packaging test/build metadata into the runtime image.
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
    PATH="/app/apps/oracle-attester/.venv/bin:${PATH}" \
    PYTHONPATH="/app/apps/oracle-attester"

WORKDIR /app/apps/oracle-attester

COPY --from=builder /app/apps/oracle-attester/.venv /app/apps/oracle-attester/.venv
COPY apps/oracle-attester/src/ /app/apps/oracle-attester/src/
COPY apps/oracle-attester/scripts/ /app/apps/oracle-attester/scripts/

# Preserve existing operational script path without duplicating source.
RUN mkdir -p /app/resolver_store /app/proof_store /app/audit /app/runtime \
    && ln -s /app/apps/oracle-attester/scripts /app/scripts

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
