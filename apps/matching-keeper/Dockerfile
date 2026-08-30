# Pin the reviewed official Python 3.11/Trixie base.  Runtime packages are
# supplied solely by this digest; do not introduce an unpinned apt upgrade.
ARG PYTHON_BASE_IMAGE=python:3.11.15-slim-trixie@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff
ARG SQLITE_SOURCE_URL=https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz
ARG SQLITE_SOURCE_SHA256=0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c

FROM ${PYTHON_BASE_IMAGE} AS sqlite-builder

ARG SQLITE_SOURCE_URL
ARG SQLITE_SOURCE_SHA256

RUN apt-get update \
    && apt-get install --no-install-recommends --yes build-essential ca-certificates \
    && python -c 'from urllib.request import urlopen; open("/tmp/sqlite.tar.gz", "wb").write(urlopen("'"${SQLITE_SOURCE_URL}"'", timeout=60).read())' \
    && echo "${SQLITE_SOURCE_SHA256}  /tmp/sqlite.tar.gz" | sha256sum -c - \
    && mkdir /tmp/sqlite \
    && tar -xzf /tmp/sqlite.tar.gz -C /tmp/sqlite --strip-components=1 \
    && cd /tmp/sqlite \
    && ./configure --prefix=/opt/sqlite --enable-fts5 --disable-static \
    && make -j"$(nproc)" \
    && make install \
    && test "$(/opt/sqlite/bin/sqlite3 --version | awk '{print $1}')" = "3.53.4" \
    && mkdir -p /tmp/prophet-sqlite-runtime/DEBIAN /tmp/prophet-sqlite-runtime/usr/local/lib \
    && cp /opt/sqlite/lib/libsqlite3.so.3.53.4 /tmp/prophet-sqlite-runtime/usr/local/lib/ \
    && ln -s libsqlite3.so.3.53.4 /tmp/prophet-sqlite-runtime/usr/local/lib/libsqlite3.so.0 \
    && printf '%s\n' \
        'Package: prophet-sqlite-runtime' \
        'Version: 3.53.4' \
        "Architecture: $(dpkg --print-architecture)" \
        'Maintainer: Prophet Protocol Infrastructure' \
        'Provides: libsqlite3-0 (= 3.53.4)' \
        'Description: Prophet-pinned SQLite runtime library' \
        > /tmp/prophet-sqlite-runtime/DEBIAN/control \
    && dpkg-deb --build --root-owner-group /tmp/prophet-sqlite-runtime /tmp/prophet-sqlite-runtime.deb

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

RUN .venv/bin/python -m pip install --no-cache-dir --upgrade     "jaraco.context==6.1.0"     "wheel==0.46.2"     && .venv/bin/python -m pip check


FROM ${PYTHON_BASE_IMAGE} AS runtime

# DSA-6442-1 fixes CVE-2026-53612 through CVE-2026-53615 in Trixie.  Pin each
# affected binary package explicitly rather than performing a mutable broad OS
# upgrade.  Refresh this list only through a reviewed base/security update.
ARG UTIL_LINUX_SECURITY_VERSION=2.41.5-0+deb13u1
ARG BSDUTILS_SECURITY_VERSION=1:2.41.5-0+deb13u1
ARG LOGIN_SECURITY_VERSION=1:4.16.0-2+really2.41.5-0+deb13u1
RUN apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install --only-upgrade --no-install-recommends --yes \
        "bsdutils=${BSDUTILS_SECURITY_VERSION}" \
        "libblkid1=${UTIL_LINUX_SECURITY_VERSION}" \
        "liblastlog2-2=${UTIL_LINUX_SECURITY_VERSION}" \
        "libmount1=${UTIL_LINUX_SECURITY_VERSION}" \
        "libsmartcols1=${UTIL_LINUX_SECURITY_VERSION}" \
        "libuuid1=${UTIL_LINUX_SECURITY_VERSION}" \
        "login=${LOGIN_SECURITY_VERSION}" \
        "mount=${UTIL_LINUX_SECURITY_VERSION}" \
        "util-linux=${UTIL_LINUX_SECURITY_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

ARG IMAGE_REVISION=unknown
ARG IMAGE_VERSION=dev
ARG IMAGE_SOURCE=https://github.com/dlavlinskovcpp/prophet

LABEL org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.source="${IMAGE_SOURCE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME="/nonexistent" \
    TMPDIR="/tmp" \
    XDG_CACHE_HOME="/tmp/.cache" \
    PATH="/app/apps/matching-keeper/.venv/bin:${PATH}" \
    PYTHONPATH="/app/apps/matching-keeper"

WORKDIR /app/apps/matching-keeper

COPY --from=builder /app/apps/matching-keeper/.venv /app/apps/matching-keeper/.venv

# Debian Trixie has no fixed package for the current SQLite FTS5 advisories.
# Replace only the runtime library with an authenticated, locally packaged
# upstream release while preserving the ABI required by liblastlog2.
COPY --from=sqlite-builder /tmp/prophet-sqlite-runtime.deb /tmp/prophet-sqlite-runtime.deb
RUN dpkg --install /tmp/prophet-sqlite-runtime.deb \
    && dpkg --purge libsqlite3-0 \
    && ldconfig \
    && rm /tmp/prophet-sqlite-runtime.deb \
    && python -c 'import sqlite3; assert sqlite3.sqlite_version == "3.53.4"'

# The keeper runs installed application code only.  Package-management tools
# are intentionally absent from the final runtime image.
RUN rm -rf \
        /usr/local/bin/pip \
        /usr/local/bin/pip3 \
        /usr/local/bin/pip3.11 \
        /usr/local/lib/python3.11/ensurepip \
        /usr/local/lib/python3.11/site-packages/pip \
        /usr/local/lib/python3.11/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.11/site-packages/setuptools \
        /usr/local/lib/python3.11/site-packages/setuptools-*.dist-info \
        /usr/local/lib/python3.11/site-packages/wheel \
        /usr/local/lib/python3.11/site-packages/wheel-*.dist-info \
        /app/apps/matching-keeper/.venv/bin/pip \
        /app/apps/matching-keeper/.venv/bin/pip3 \
        /app/apps/matching-keeper/.venv/bin/pip3.11 \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/pip \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/pip-*.dist-info \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/setuptools \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/setuptools-*.dist-info \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/wheel \
        /app/apps/matching-keeper/.venv/lib/python3.11/site-packages/wheel-*.dist-info
# prophet-sdk is an editable path dependency for the keeper, so retain exactly
# its expected repository-relative runtime path rather than duplicating it.
COPY sdk/python/prophet_sdk/ /app/sdk/python/prophet_sdk/
COPY apps/matching-keeper/src/ /app/apps/matching-keeper/src/

# Fixed application identity. The application source, SDK code, and virtualenv
# remain root-owned; the keeper state directory is the only writable image path.
RUN groupadd --system --gid 10001 prophet \
    && useradd --system --uid 10001 --gid prophet --home-dir /nonexistent --shell /usr/sbin/nologin prophet \
    && mkdir -p /app/apps/matching-keeper/state \
    && chown prophet:prophet /app/apps/matching-keeper/state

USER 10001:10001

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=3).read()" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "127.0.0.1", "--port", "8010"]
