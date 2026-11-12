FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Sin dependencias: la consola y el generador de credenciales usan solo la biblioteca estándar.
COPY *.py ./
COPY static ./static

# La consola corre sin privilegios. El servicio `init` usa esta misma imagen pero arranca como root (ver docker-compose.yml),
# porque tiene que escribir en el volumen de credenciales.
RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin demo
USER demo

EXPOSE 8080

CMD ["python", "server.py"]
