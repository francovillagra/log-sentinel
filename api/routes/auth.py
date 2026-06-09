from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from api.services.auth_service import create_access_token, verify_password

router = APIRouter(prefix="/api/v1")


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    pool = request.app.state.db_pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash FROM users WHERE email = $1",
            body.email,
        )

    # Same response for unknown email and wrong password — avoid user enumeration.
    if row is None or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    token = create_access_token(body.email)
    return LoginResponse(access_token=token)
