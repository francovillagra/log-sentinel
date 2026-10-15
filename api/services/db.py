import logging
import os
import ssl
from typing import Optional, Union

import asyncpg

log = logging.getLogger(__name__)

_pool: Optional[asyncpg.Pool] = None


def build_ssl_context() -> Union[ssl.SSLContext, str]:
    """
    TLS hacia la base de datos, según DATABASE_SSL_MODE (como libpq):

    - `verify-full`: verifica el certificado contra DATABASE_SSL_CA y que el nombre del servidor coincida.
    - `verify-ca`: verifica el certificado contra DATABASE_SSL_CA, sin mirar el nombre.
    - `require` (por defecto): cifra pero NO verifica: quien esté en el camino puede hacerse pasar por la base y
      leer o cambiar lo que viaja (alertas y el hash de la contraseña). Se mantiene para no romper despliegues que
      todavía no tienen el certificado; arranca con una advertencia.
    - `disable`: sin TLS. Solo para una base local de desarrollo o de pruebas (p. ej. un contenedor en la misma
      máquina); arranca con una advertencia.

    DATABASE_SSL_CA es el certificado de la CA (el texto PEM o la ruta a un archivo). Supabase lo ofrece en
    Database > Settings > SSL Configuration.
    """
    mode = os.environ.get("DATABASE_SSL_MODE", "require").strip().lower()
    if mode not in ("disable", "require", "verify-ca", "verify-full"):
        raise RuntimeError("DATABASE_SSL_MODE tiene que ser disable, require, verify-ca o verify-full.")

    if mode == "disable":
        log.warning("DATABASE_SSL_MODE=disable: la conexión a la base va SIN cifrar. Usalo solo con una base local.")
        return "disable"  # asyncpg: con ssl=None probaría TLS primero ("prefer"); así no lo intenta

    if mode == "require":
        log.warning(
            "DATABASE_SSL_MODE=require: la conexión a la base va cifrada pero no se verifica el certificado del "
            "servidor. Configurá DATABASE_SSL_CA y DATABASE_SSL_MODE=verify-full."
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ca = os.environ.get("DATABASE_SSL_CA", "").strip()
    if not ca:
        raise RuntimeError(f"DATABASE_SSL_MODE={mode} necesita DATABASE_SSL_CA (el certificado de la CA, en PEM o la ruta).")
    ctx = ssl.create_default_context(cadata=ca) if "BEGIN CERTIFICATE" in ca else ssl.create_default_context(cafile=ca)
    ctx.check_hostname = mode == "verify-full"
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def get_pool() -> asyncpg.Pool:
    """
    Lazy singleton: create the asyncpg connection pool on first call.

    DATABASE_URL must be the Supabase *session pooler* connection string.
    SSL is provided as an ssl.SSLContext keyword arg (NOT as a URL parameter),
    which is what asyncpg expects against Supabase.
    """
    global _pool
    if _pool is None:
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            raise RuntimeError("DATABASE_URL is not configured")
        _pool = await asyncpg.create_pool(
            dsn, ssl=build_ssl_context(), min_size=1, max_size=5, command_timeout=30
        )
    return _pool
