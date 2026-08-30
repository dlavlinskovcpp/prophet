"""Retired ASGI compatibility module for the legacy dual-token service."""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .secure_settlement_bootstrap import LegacySecureSettlementRetired


@asynccontextmanager
async def _retired_lifespan(_: FastAPI):
    # Importing the former Uvicorn target remains safe for packaging checks, but
    # a server cannot start it or reach any runtime/credential acquisition.
    raise LegacySecureSettlementRetired("legacy_secure_settlement_retired")
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_retired_lifespan)
