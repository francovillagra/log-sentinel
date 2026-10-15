from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import allowed_origins


def setup_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(),
        # La sesión viaja en el encabezado Authorization, no en cookies: no hace falta permitir credenciales.
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
        expose_headers=["Retry-After"],  # para que el dashboard pueda decir cuánto esperar tras un 429
    )
