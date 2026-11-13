"""Genera las credenciales de la demo, una sola vez, en el volumen `demo_credentials`.

Nada de esto vive en el repositorio: cada computadora genera las suyas la primera vez que arranca la demo y las guarda en un
volumen de Docker. Las lee quien las necesita (la API, la base y la consola de práctica). Si el volumen ya las tiene, no las
toca; `docker compose down -v` borra el volumen y la próxima vez se generan otras.

No imprime ninguna credencial: la consola de práctica muestra la que hace falta para entrar al panel.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

DIRECTORY = Path(os.environ.get("DEMO_SECRETS_DIR", "/run/demo"))
ADMIN_EMAIL = "demo@log-sentinel.test"      # .test está reservado: no existe en internet

# Los mismos fragmentos que rechaza api/config.py. Un valor generado al azar casi nunca los trae, pero si pasara, la API
# se negaría a arrancar: por eso se comprueban acá también.
EXAMPLE_MARKERS = (
    "change-me", "change_me", "changeme", "example", "placeholder", "your-secret", "your_secret",
    "secret-here", "secret_here", "supersecret", "super-secret", "before-deploy",
)

# Palabras cortas y sin acentos, fáciles de dictar y de escribir con cualquier teclado.
WORDS = (
    "abeto", "aguila", "alamo", "almeja", "arce", "arena", "atlas", "aurora", "avena", "azor", "bahia", "balsa", "barco",
    "bosque", "brisa", "bruma", "cabra", "cactus", "caleta", "campo", "canoa", "castor", "cedro", "cerro", "chispa", "cielo",
    "cobre", "colina", "coral", "cuarzo", "delta", "duna", "enebro", "escudo", "espiga", "estrella", "faro", "fresno",
    "fuego", "gaviota", "geiser", "glaciar", "granito", "grulla", "halcon", "helecho", "hielo", "hornero", "huerto", "isla",
    "jade", "jaguar", "jilguero", "junco", "lago", "laguna", "lava", "lince", "llama", "lluvia", "luna", "marea", "meseta",
    "miel", "monte", "musgo", "nevada", "nido", "niebla", "nogal", "nube", "oasis", "ocaso", "olivo", "onda", "opalo",
    "orilla", "paloma", "pampa", "pantano", "pino", "plata", "playa", "pradera", "puma", "puente", "rama", "roble", "roca",
    "rocio", "salina", "sauce", "selva", "sierra", "tormenta", "tierra", "tilo", "tigre", "trigo", "tucan", "valle", "vega",
    "viento", "volcan", "zafiro", "zorro",
)


def is_strong(value: str, min_length: int, min_distinct: int) -> bool:
    return (
        len(value) >= min_length
        and len(set(value)) >= min_distinct
        and not any(marker in value.lower() for marker in EXAMPLE_MARKERS)
    )


def new_token(nbytes: int) -> str:
    while True:
        value = secrets.token_urlsafe(nbytes)
        if is_strong(value, 32, 8):
            return value


def new_passphrase() -> str:
    """Tres palabras y dos cifras ('faro-cobre-nube-47'): se dicta y se escribe en vivo sin errores."""
    while True:
        words = [secrets.choice(WORDS) for _ in range(3)]
        value = "-".join(words) + f"-{secrets.randbelow(90) + 10}"
        if len(set(words)) == 3 and is_strong(value, 12, 6):
            return value


def write_if_missing(name: str, make) -> bool:
    path = DIRECTORY / name
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return False
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(make() + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)  # las leen la base, la API y la consola, cada una con su propio usuario
    os.replace(tmp, path)
    return True


def main() -> int:
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    created = [
        write_if_missing("postgres_password", lambda: secrets.token_hex(24)),
        write_if_missing("jwt_secret", lambda: new_token(48)),
        write_if_missing("ingest_api_key", lambda: new_token(36)),
        write_if_missing("admin_email", lambda: ADMIN_EMAIL),
        write_if_missing("admin_password", new_passphrase),
    ]
    print("Credenciales de la demo: " + ("generadas." if any(created) else "ya existían, se conservan."), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
