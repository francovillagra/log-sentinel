FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Las dependencias van primero (con versiones fijas): la capa se reutiliza mientras no cambie requirements.txt.
COPY requirements.txt .
RUN pip install -r requirements.txt

# La API corre sin privilegios: una falla en el servicio no da root dentro del contenedor.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser

# Solo lo que la API necesita para correr (ni pruebas, ni la web, ni la documentación).
COPY --chown=appuser:appuser api ./api
COPY --chown=appuser:appuser engine ./engine

USER appuser

EXPOSE 8000

# exec: uvicorn queda como proceso principal y recibe las señales de parada.
# --no-server-header: no anuncia qué servidor es. --no-proxy-headers: la IP del cliente la resuelve la propia API
# (api/security.py, con TRUSTED_PROXY_COUNT), no uvicorn. --ws-max-size: el panel no manda mensajes al servidor,
# así que 4 KB sobran (el valor por defecto es 16 MB).
CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header --no-proxy-headers --ws-max-size 4096"]
