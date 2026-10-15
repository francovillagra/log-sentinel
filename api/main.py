import asyncio
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from api.config import docs_enabled, max_request_bytes, validate_admin_password, validate_environment
from api.middleware.cors import setup_cors
from api.routes.alerts_history import router as alerts_history_router
from api.routes.auth import router as auth_router
from api.routes.health import router as health_router
from api.routes.ingest import router as ingest_router
from api.routes.ws import router as ws_router
from api.security import BodyLimitMiddleware, SecurityHeadersMiddleware, security_headers
from api.services.auth_service import hash_password_async
from api.services.broadcaster import broadcaster
from api.services.db import get_pool
from api.services.redis_client import get_redis
from api.services.stream import read_new_alerts
from engine.detectors.brute_force import BruteForceDetector
from engine.detectors.injection import SqlInjectionDetector, XssDetector
from engine.detectors.path_traversal import PathTraversalDetector
from engine.detectors.rate_anomaly import RateAnomalyDetector
from engine.detectors.user_agent import SuspiciousUserAgentDetector
from engine.engine import Engine
from engine.parsers.jsonl import JsonLinesParser
from engine.parsers.nginx import NginxCombinedParser

load_dotenv()
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_TOKEN_IN_URL = re.compile(r"([?&]token=)[^&\s\"']+")


class RedactTokens(logging.Filter):
    """El navegador no puede mandar encabezados en un WebSocket: el token de sesión viaja en la URL
    (`/ws/alerts?token=...`) y uvicorn la escribe tal cual en su registro. Se tacha antes de escribirla, para que
    una sesión válida no quede en los logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(_TOKEN_IN_URL.sub(r"\1<oculto>", a) if isinstance(a, str) else a for a in record.args)
        return True


# uvicorn escribe las conexiones WebSocket en "uvicorn.error" y los pedidos HTTP en "uvicorn.access".
for _name in ("uvicorn.error", "uvicorn.access"):
    logging.getLogger(_name).addFilter(RedactTokens())


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


async def ensure_admin_user(pool) -> None:
    """Seed the initial admin user if the users table is empty.

    ADMIN_PASSWORD solo hace falta (y solo se valida) cuando hay que crear la cuenta: una vez creada se puede
    sacar del entorno, así la contraseña del administrador no queda guardada en la configuración del servicio."""
    email = os.environ.get("ADMIN_EMAIL", "admin@log-sentinel.dev").strip().lower()

    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM users")
        if count == 0:
            password = os.environ.get("ADMIN_PASSWORD")
            if not password:
                raise RuntimeError("ADMIN_PASSWORD is not configured (hace falta para crear el primer administrador)")
            # Una contraseña débil acá es la del administrador de todo el panel.
            validate_admin_password(password)
            await conn.execute(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
                email,
                await hash_password_async(password),
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
    # Primero los secretos: con uno de ejemplo o débil la API no arranca (mensaje claro en el log).
    validate_environment()

    app.state.engine = build_engine()
    app.state.redis = await get_redis()
    log.info("engine and redis client initialized")

    app.state.db_pool = await get_pool()
    log.info("database pool initialized")

    await ensure_admin_user(app.state.db_pool)
    log.info("admin user ready")

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
    await app.state.db_pool.close()
    log.info("shutdown complete")


def create_app(with_lifespan: bool = True) -> FastAPI:
    docs = docs_enabled()
    app = FastAPI(
        title="log-sentinel API",
        version="2.0.0",
        description="Blue Team SIEM-lite — Phase 2 API",
        lifespan=lifespan if with_lifespan else None,
        # La documentación de la API (y el esquema con todas las rutas) solo con DEBUG=true.
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )

    # Starlette pone el último middleware agregado como el más externo. CORS va afuera de todo: contesta las
    # consultas previas y agrega sus encabezados también a las respuestas de error. El tope de cuerpo va adentro
    # de todo, así su respuesta también lleva las cabeceras de seguridad.
    app.add_middleware(BodyLimitMiddleware, max_bytes=max_request_bytes())
    app.add_middleware(SecurityHeadersMiddleware)
    setup_cors(app)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # La respuesta por defecto de FastAPI repite el valor recibido ("input"): en un login es la contraseña, y
        # en /ingest serían megabytes de vuelta.
        errors = [{"type": e.get("type"), "loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"}, headers=security_headers())

    app.include_router(health_router)
    app.include_router(ingest_router)
    app.include_router(ws_router)
    app.include_router(auth_router)
    app.include_router(alerts_history_router)
    return app


app = create_app()
