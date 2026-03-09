import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Query

from .config import settings
from .service import MatchingKeeperService


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

service = MatchingKeeperService(settings)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await service.start()
    try:
        yield
    finally:
        await service.stop()


app = FastAPI(title="Prophet Matching Keeper", lifespan=lifespan)


@app.get("/health")
def health():
    return service.health()


@app.get("/markets")
def markets():
    return {"markets": service.market_statuses()}


@app.get("/attempts")
def attempts(limit: int = Query(default=50, ge=1, le=500)):
    return {"attempts": service.recent_attempts(limit)}


def serve() -> None:
    uvicorn.run("src.main:app", host="0.0.0.0", port=8010, reload=False)


if __name__ == "__main__":
    serve()
