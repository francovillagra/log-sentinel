import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/health")
async def health():
    key = os.getenv("INGEST_API_KEY", "")
    return JSONResponse({
        "status": "ok",
        "key_present": bool(key),
        "key_length": len(key)
    })
