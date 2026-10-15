import logging

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.ratelimit import SlidingWindowLimiter
from api.security import rate_limit_key
from api.services.auth_service import (
    PasswordWorkBusy,
    create_access_token,
    verify_password_async,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Cada intento de login cuesta un bcrypt y puede ser una adivinanza de contraseña. El cupo se reserva ANTES de
# calcular el hash (así los pedidos en paralelo tampoco lo esquivan) y se devuelve si el login resulta correcto:
# lo que se cuenta son los fallos. Se limita por dirección y por dirección + cuenta; no por cuenta sola, porque
# entonces cualquiera podría bloquear la cuenta del administrador desde su propia dirección.
_login_ip_limiter = SlidingWindowLimiter(limit=30, window_seconds=900)
_login_account_limiter = SlidingWindowLimiter(limit=8, window_seconds=900)


class LoginRequest(BaseModel):
    # Topes de tamaño: sin ellos un cuerpo de megabytes llegaba hasta bcrypt y la base de datos.
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _too_many(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Demasiados intentos fallidos. Probá de nuevo más tarde.",
        headers={"Retry-After": str(wait)},
    )


@router.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    email = body.email.strip().lower()
    ip_key = rate_limit_key(request)
    account_key = f"{ip_key}|{email}"

    # Antes de tocar la base o calcular nada: un cliente bloqueado no gasta CPU.
    wait = _login_ip_limiter.hit(ip_key)
    if wait is not None:
        raise _too_many(wait)
    wait = _login_account_limiter.hit(account_key)
    if wait is not None:
        _login_ip_limiter.refund(ip_key)
        raise _too_many(wait)

    valid = False
    evaluated = False
    try:
        pool = request.app.state.db_pool
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT password_hash FROM users WHERE lower(email) = $1", email)
        # Corre bcrypt incluso si el usuario no existe: la respuesta tarda lo mismo.
        valid = await verify_password_async(body.password, row["password_hash"] if row else None)
        evaluated = True
    except PasswordWorkBusy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servidor está ocupado. Probá de nuevo en unos segundos.",
            headers={"Retry-After": "5"},
        )
    finally:
        if not evaluated:  # no se llegó a probar la contraseña: se devuelve el cupo
            _login_ip_limiter.refund(ip_key)
            _login_account_limiter.refund(account_key)

    # Same response for unknown email and wrong password — avoid user enumeration.
    if not valid:
        if _login_account_limiter.retry_after(account_key) is not None:
            logger.warning("Login bloqueado por demasiados fallos desde %s", ip_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    _login_ip_limiter.refund(ip_key)
    _login_account_limiter.clear(account_key)
    return LoginResponse(access_token=create_access_token(email))
