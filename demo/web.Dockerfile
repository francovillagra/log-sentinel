# El panel de avisos (web/) en producción, para la demo local.
#
# NEXT_PUBLIC_* se fija al construir (Next.js lo reemplaza en el código): por eso llegan como argumentos de construcción.
# docker-compose.yml les pone la dirección de la API de la demo.
FROM node:22-slim

ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app
RUN chown node:node /app
USER node

# Primero las dependencias: la capa se reutiliza mientras no cambien package.json ni package-lock.json.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

ARG NEXT_PUBLIC_API_URL=http://localhost:4002
ARG NEXT_PUBLIC_WS_URL=ws://localhost:4002/ws/alerts
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL}

# El build también revisa los tipos. Las fuentes de Google se descargan acá y quedan dentro de la imagen.
RUN npm run build

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node_modules/.bin/next", "start", "-H", "0.0.0.0", "-p", "3000"]
