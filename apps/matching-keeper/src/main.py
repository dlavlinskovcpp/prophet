import logging
import hmac
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .config import Settings
from .service import MatchingKeeperService


settings = Settings()

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


def _ops_authorized(request: Request) -> bool:
    if not settings.OPS_PROTECTED_INGRESS:
        return False
    token = request.headers.get("x-prophet-ops-token", "")
    return bool(token) and hmac.compare_digest(token, settings.OPS_API_AUTH_TOKEN)


@app.get("/markets")
def markets(request: Request):
    if not settings.OPS_EXPOSE_MARKETS or not _ops_authorized(request):
        return JSONResponse(status_code=404, content={"error": "ops_endpoint_disabled"})
    return {"markets": service.market_statuses()}


@app.get("/attempts")
def attempts(request: Request, limit: int = Query(default=50, ge=1, le=500)):
    if not settings.OPS_EXPOSE_ATTEMPTS or not _ops_authorized(request):
        return JSONResponse(status_code=404, content={"error": "ops_endpoint_disabled"})
    return {"attempts": service.recent_attempts(limit)}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    if not settings.OPS_EXPOSE_METRICS or not _ops_authorized(request):
        return PlainTextResponse("ops_endpoint_disabled\n", status_code=404)
    return service.metrics_text()


def serve() -> None:
    settings.validate_runtime()
    uvicorn.run("src.main:app", host=settings.OPS_HOST, port=settings.OPS_PORT, reload=False)


if __name__ == "__main__":
    serve()
