import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI

from engine.detectors.brute_force import BruteForceDetector
from engine.detectors.injection import SqlInjectionDetector, XssDetector
from engine.detectors.path_traversal import PathTraversalDetector
from engine.detectors.rate_anomaly import RateAnomalyDetector
from engine.detectors.user_agent import SuspiciousUserAgentDetector
from engine.engine import Engine
from engine.parsers.jsonl import JsonLinesParser
from engine.parsers.nginx import NginxCombinedParser
from api.middleware.cors import setup_cors
from api.routes.health import router as health_router
from api.routes.ingest import router as ingest_router
from api.routes.ws import router as ws_router
from api.services.broadcaster import broadcaster
from api.services.redis_client import get_redis
from api.services.stream import read_new_alerts

load_dotenv()
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def build_engine() -> Engine:
    """Create the shared Engine with all parsers and detectors."""
    return Engine(
        parsers=[JsonLinesParser(), NginxCombinedParser()],
        detectors=[
            BruteForceDetector(),
            SqlInjectionDetector(),
            XssDetector(),
            PathTraversalDetector(),
            SuspiciousUserAgentDetector(),
            RateAnomalyDetector(),
        ],
    )


async def broadcast_loop() -> None:
    """
    Background task: read new alerts from the Redis Stream and push them
    to all connected WebSocket clients. Retries on any error after 2s.
    """
    last_id = "$"
    while True:
        try:
            redis = await get_redis()
            entries = await read_new_alerts(redis, last_id)
            for stream_id, alert_dict in entries:
                last_id = stream_id
                await broadcaster.broadcast(json.dumps(alert_dict))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("broadcast_loop error: %s — retrying in 2s", exc)
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.engine = build_engine()
    app.state.redis = await get_redis()
    log.info("engine and redis client initialized")

    task = asyncio.create_task(broadcast_loop())
    app.state.broadcaster_task = task
    log.info("broadcast_loop started")

    yield

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    await app.state.redis.aclose()
    log.info("shutdown complete")


app = FastAPI(
    title="log-sentinel API",
    version="2.0.0",
    description="Blue Team SIEM-lite — Phase 2 API",
    lifespan=lifespan,
)

setup_cors(app)
app.include_router(health_router)
app.include_router(ingest_router)
app.include_router(ws_router)
