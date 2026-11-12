# Demo local de Log-Sentinel

El sistema completo (API, motor de detección, Redis, PostgreSQL y el panel de avisos) más una **consola de práctica** con botones, todo en esta computadora y con un solo comando. Sirve para ver cómo Log-Sentinel detecta ataques en tiempo real, sin tocar ningún sitio real.

```
Consola de práctica ── POST /api/v1/ingest ──▶ API ──▶ motor de detección ──▶ Redis ──▶ WebSocket ──▶ Panel de avisos
   localhost:4000      (con la clave de ingesta)  :4002      (las 6 reglas)                                 localhost:4001
```

Cada botón de la consola arma líneas de log como las que escribiría un servidor web (formato nginx) y las manda al mismo endpoint que usaría un servidor real. Lo que se ve en el panel es la detección verdadera del motor, no una animación.

## Qué se necesita

- **Docker Desktop** (Windows con WSL2, macOS o Linux) o Docker Engine con Compose v2. Comprobar con `docker compose version`.
- Unos 2 GB libres y conexión a internet **solo para construir** la primera vez (imágenes y paquetes). Después funciona sin internet.

## Arrancar

Desde una terminal (PowerShell, cmd, bash), en la carpeta `demo/` del repositorio:

```bash
cd demo
docker compose up --build
```

La primera vez tarda unos minutos porque construye las imágenes. Cuando aparece `Consola de práctica lista`, abrir **http://localhost:4000**.

Para dejarlo en segundo plano, esperando a que todo esté sano, y apagarlo después:

```bash
docker compose up -d --build --wait
docker compose down
```

## Cómo usarla

1. Abrir la consola: http://localhost:4000. Arriba a la derecha dice **Sistema listo** cuando todo responde.
2. Pulsar **Abrir el panel**. Se abre en otra pestaña o ventana; conviene dejarlo al lado de la consola para ver los avisos aparecer en vivo. El usuario y la contraseña están en la consola (**Mostrar** / **Copiar**).
3. Elegir una prueba y pulsar **Probar**. La consola muestra qué se envió y qué detectó el sistema; el panel muestra el aviso al instante.

| Prueba | Qué simula | Regla que debe saltar |
|---|---|---|
| Un día normal en el sitio | 24 visitas comunes de clientes | ninguna (así se ve cuando todo está bien) |
| Alguien prueba contraseñas | Un programa prueba claves una tras otra | `brute_force` |
| Intentan sacar datos de clientes | Órdenes de base de datos escondidas en una dirección web | `sqli` |
| Ataque en varias etapas | El mismo atacante revisa, prueba claves, saca datos, lee archivos y satura | `suspicious_ua`, `brute_force`, `sqli`, `path_traversal` y `rate_anomaly`, una cada pocos segundos |
| Meten un script en el buscador | Código colado en un campo del sitio | `xss` |
| Intentan leer archivos privados | Pedidos de `/.env`, `/.git/config`, `../../etc/passwd` | `path_traversal` |
| Un programa de ataque revisa el sitio | Herramientas conocidas (sqlmap, Nikto, WPScan) con su nombre | `suspicious_ua` |
| Ráfaga de visitas | 120 pedidos en pocos segundos desde un mismo origen | `rate_anomaly` |

Cada clic usa una dirección de atacante distinta, así que se puede repetir una prueba las veces que haga falta y el panel siempre avisa. **Vaciar la lista** limpia el registro de la consola; el panel tiene su propio botón **Clear**.

> El panel de avisos es el mismo de `web/` y está en inglés. La consola de práctica, en español.

## Direcciones y puertos

| Qué | Dirección | Variable para cambiar el puerto |
|---|---|---|
| Consola de práctica | http://localhost:4000 | `DEMO_CONSOLE_PORT` |
| Panel de avisos | http://localhost:4001 | `DEMO_WEB_PORT` |
| API | http://localhost:4002 | `DEMO_API_PORT` |

Si algún puerto está ocupado, elegir otro **antes de construir** (el panel guarda la dirección de la API al construirse):

```powershell
# PowerShell
$env:DEMO_WEB_PORT = 3100
docker compose up --build
```

```bash
# bash / zsh
DEMO_WEB_PORT=3100 docker compose up --build
```

## Apagar, reiniciar y empezar de cero

| Comando | Efecto |
|---|---|
| `Ctrl + C` (en primer plano) o `docker compose down` | Apaga todo. La base vive en memoria: la próxima vez empieza vacía. |
| `docker compose down -v` | Además borra las credenciales generadas; la próxima vez se crean otras. |
| `docker compose up` (sin `--build`) | Vuelve a encender sin reconstruir. |

## Seguridad de la demo

- **Solo local.** Los puertos se publican en `127.0.0.1`: nadie de la red local puede entrar. La base y Redis no publican ninguno.
- **Sin credenciales en el repositorio.** La primera vez, un servicio (`init`, ver `console/make_secrets.py`) genera al azar las claves y la contraseña de acceso y las guarda en un volumen de Docker. La API se niega a arrancar con secretos débiles, y estos cumplen sus mismas reglas.
- **Datos de práctica.** Las direcciones de los "atacantes" pertenecen a los bloques que el estándar RFC 5737 reserva para documentación (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`): no son de nadie y no hay ningún destino real.
- **La consola no ataca nada.** Solo manda líneas de log de práctica al sistema local. Acepta pedidos únicamente de su propia página (controla `Host` y `Origin`), de modo que otro sitio abierto en el navegador no puede dispararla.
- **Contenedores acotados.** Los tres servicios propios corren sin root, sin privilegios extra y sin capacidades de Linux.
- Esto es una demo en una computadora personal: no está pensada para exponerse en una red ni en internet.

## Problemas frecuentes

| Síntoma | Qué hacer |
|---|---|
| `Cannot connect to the Docker daemon` | Abrir Docker Desktop y esperar a que indique que el motor está en ejecución. |
| Un puerto está ocupado | Elegir otro con las variables de la tabla de puertos y construir de nuevo. |
| La consola no pasa de «Esperando que el sistema termine de arrancar…» | Ver qué falla con `docker compose ps` y `docker compose logs api`. |
| El panel rechaza la contraseña después de reconstruir | Quedaron credenciales viejas en el volumen: `docker compose down -v` y volver a arrancar. |
| La primera construcción es lenta | Es normal (descarga imágenes y paquetes). Las siguientes usan la caché. |

## Cómo está armado

```
demo/
├── docker-compose.yml        # init, postgres, redis, api, web (panel) y console
├── web.Dockerfile            # construye el panel de web/ apuntando a la API local
└── console/
    ├── server.py             # servidor de la consola (solo biblioteca estándar de Python)
    ├── scenarios.py          # las pruebas: arman las líneas de log de práctica
    ├── make_secrets.py       # genera las credenciales la primera vez
    ├── static/               # la página con los botones (HTML, CSS, JS)
    └── Dockerfile
```

Las pruebas automáticas de la demo no necesitan Docker: ejecutan cada escenario contra el motor real, comprueban que saltan las reglas esperadas (y que el tráfico normal no dispara nada) y revisan la seguridad de la consola.

```bash
python -m pytest tests/demo -q
```
