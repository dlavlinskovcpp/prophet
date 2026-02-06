import logging
from fastapi import FastAPI, HTTPException
from .config import settings
from .types import ResolveRequest, ResolveResponse


def _validate_runtime() -> None:
    settings.validate_zktls_runtime()

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("oracle-attester")

_validate_runtime()

from .attester import service

app = FastAPI(title="Prophet Oracle Attester")

@app.get("/health")
def health_check():
    return {
        "ok": True,
        "zktls_mode": settings.ZKTLS_MODE,
        "require_zktls": settings.REQUIRE_ZKTLS,
        "app_env": settings.APP_ENV,
    }

@app.post("/resolve", response_model=ResolveResponse)
async def resolve_market_endpoint(req: ResolveRequest):
    logger.info(f"Request: Resolve {req.market} -> {req.outcome}")
    try:
        resp = await service.resolve_market(req)
        logger.info(f"Success: {req.market} resolved in tx {resp.signature}")
        return resp
    except LookupError as e:
        logger.warning(f"Not Found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        logger.warning(f"Forbidden: {e}")
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        logger.warning(f"Conflict: {e}")
        # 409 Conflict covers "already resolved" or "too early" or "in flight"
        raise HTTPException(status_code=409, detail=str(e))
    except RuntimeError as e:
        logger.error(f"Tx Failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception(f"Internal Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
