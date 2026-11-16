"""Comprobaciones de la demo en Docker para la verificación temporal (rama tmp/verificacion-docker-log-sentinel).

Se corre dentro de demo/, con la demo ya encendida:

    python3 ../.github/tmp-verificacion/checks.py estado
    python3 ../.github/tmp-verificacion/checks.py seguridad

Imprime una línea por comprobación (OK / FALLA), deja un resumen en el panel del job y termina con código 1 si alguna falla.
La demo de Log-Sentinel no trae una «Prueba de aceptación» escrita: se comprueba lo que su README promete (todo sano, puertos solo en
127.0.0.1 y solo los tres que se dicen, servicios propios sin root y sin privilegios, credenciales que no se imprimen) leyéndolo de los
contenedores en ejecución.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request

PROJECT = "log-sentinel-demo"
EXPECTED_PORTS = {
    "console": ["127.0.0.1:4000->8080/tcp"],
    "web": ["127.0.0.1:4001->3000/tcp"],
    "api": ["127.0.0.1:4002->8000/tcp"],
}
SECRETS = ("jwt_secret", "ingest_api_key", "admin_password", "postgres_password")


def run(args, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class Report:
    def __init__(self, title: str):
        self.title = title
        self.lines: list[str] = []
        self.failed = 0

    def check(self, ok: bool, text: str) -> None:
        line = f"{'OK   ' if ok else 'FALLA'} {text}"
        self.lines.append(line)
        print(line, flush=True)
        if not ok:
            self.failed += 1

    def finish(self) -> int:
        total = len(self.lines)
        summary = f"{self.title}: {total - self.failed} de {total} comprobaciones en orden"
        print(summary)
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"### {self.title}\n\n```\n" + "\n".join(self.lines) + "\n```\n\n")
        if self.failed:
            failing = [line for line in self.lines if line.startswith("FALLA")]
            print(f"::error title={self.title}::{escape(summary + chr(10) + chr(10).join(failing))}")
            return 1
        print(f"::notice title={self.title}::{escape(summary + chr(10) + chr(10).join(self.lines))}")
        return 0


def compose_ps() -> dict[str, dict]:
    raw = run(["docker", "compose", "ps", "-a", "--format", "json"]).stdout.strip()
    try:
        data = json.loads(raw)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:  # versiones de Compose que escriben un objeto por línea
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return {row["Service"]: row for row in rows}


def inspect(service: str) -> dict:
    ids = run(["docker", "compose", "ps", "-a", "-q", service]).stdout.split()
    if not ids:
        return {}
    return json.loads(run(["docker", "inspect", ids[0]]).stdout)[0]


def estado() -> int:
    rep = Report("Estado de los servicios")
    rows = compose_ps()
    row = rows.get("init") or {}
    rep.check(
        row.get("State") == "exited" and row.get("ExitCode") == 0,
        f"init terminó con código 0 (estado={row.get('State')}, código={row.get('ExitCode')})",
    )
    for service in ("postgres", "redis", "api", "web", "console"):
        row = rows.get(service) or {}
        rep.check(
            row.get("State") == "running" and row.get("Health") == "healthy",
            f"{service} figura healthy (estado={row.get('State')}, salud={row.get('Health')})",
        )
    for name, url in (("API", "http://127.0.0.1:4002/health"), ("consola", "http://127.0.0.1:4000/healthz"), ("panel", "http://127.0.0.1:4001/login")):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                rep.check(response.status == 200, f"{name} responde 200 desde afuera de Docker ({url})")
        except Exception as error:  # noqa: BLE001 - se informa y se sigue
            rep.check(False, f"{name} no respondió ({url}): {error}")
    return rep.finish()


def seguridad() -> int:
    rep = Report("Comprobaciones de seguridad")
    rows = compose_ps()

    # 1) Solo se publican los tres puertos que dice el README, todos en 127.0.0.1; la base y Redis no publican ninguno.
    published = {}
    for service, row in rows.items():
        pubs = {
            f"{p.get('URL')}:{p['PublishedPort']}->{p.get('TargetPort')}/{p.get('Protocol')}"
            for p in (row.get("Publishers") or [])
            if p.get("PublishedPort")
        }
        published[service] = sorted(pubs)
    expected = {service: EXPECTED_PORTS.get(service, []) for service in rows}
    rep.check(published == expected, f"puertos publicados: {json.dumps(published)}")

    # 2) Los tres servicios propios corren sin root.
    for service in ("api", "web", "console"):
        res = run(["docker", "compose", "exec", "-T", service, "id", "-u"])
        uid = res.stdout.strip()
        rep.check(uid.isdigit() and uid != "0", f"{service} corre sin root (usuario {uid or res.stderr.strip()})")

    # 3) ...sin privilegios extra y sin capacidades de Linux, según el contenedor real.
    for service in ("api", "web", "console"):
        host = inspect(service).get("HostConfig", {})
        drop = [c.upper().removeprefix("CAP_") for c in (host.get("CapDrop") or [])]
        options = host.get("SecurityOpt") or []
        rep.check("ALL" in drop, f"{service}: descarta todas las capacidades de Linux (CapDrop={host.get('CapDrop')})")
        rep.check(any("no-new-privileges" in o for o in options), f"{service}: no-new-privileges (SecurityOpt={options})")

    # 4) Las credenciales las genera `init` y no se imprimen: ningún valor generado aparece en los registros de ningún servicio.
    #    (Los valores se leen del volumen y se comparan en memoria: no se muestran.)
    logs = run(["docker", "compose", "logs", "--no-color"], timeout=180).stdout
    for name in SECRETS:
        res = run(["docker", "compose", "exec", "-T", "console", "cat", f"/run/demo/{name}"])
        value = res.stdout.strip()
        rep.check(len(value) >= 12 and value not in logs, f"{name}: se leyó del volumen ({len(value)} caracteres) y no aparece en los registros de los servicios")

    # 5) Nada de la demo debería haberse publicado en otra interfaz que 127.0.0.1 (ya cubierto arriba) ni usar la red por defecto sin nombre.
    names = run(["docker", "network", "ls", "--filter", f"label=com.docker.compose.project={PROJECT}", "--format", "{{.Name}}"]).stdout.split()
    rep.check(len(names) >= 1, f"la demo usa su propia red de Docker ({', '.join(names)})")
    return rep.finish()


if __name__ == "__main__":
    commands = {"estado": estado, "seguridad": seguridad}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit("uso: checks.py estado|seguridad")
    sys.exit(commands[sys.argv[1]]())
