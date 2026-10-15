// Arranca el servidor de producción ya construido y comprueba las cabeceras de seguridad de cada página:
// falla si una página pierde la Content-Security-Policy, su nonce o una de las cabeceras fijas.
//   npm run build && npm run check:headers
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = process.env.CHECK_PORT ?? "3199";
const BASE = `http://127.0.0.1:${PORT}`;
// Se arranca el binario de Next directamente (sin npx): así al terminar se mata el servidor de verdad, no un envoltorio.
const nextBin = createRequire(import.meta.url).resolve("next/dist/bin/next");
const server = spawn(process.execPath, [nextBin, "start", "-p", PORT, "-H", "127.0.0.1"], { stdio: "inherit", env: process.env });

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); };

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try { await fetch(`${BASE}/login`); return; } catch { await sleep(500); }
  }
  throw new Error("el servidor no arrancó");
}

try {
  await waitForServer();
  const nonces = new Set();
  for (const path of ["/", "/login", "/no-existe"]) {
    const res = await fetch(`${BASE}${path}`);
    const html = await res.text();
    const csp = res.headers.get("content-security-policy") ?? "";
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    const script = /script-src ([^;]*)/.exec(csp)?.[1] ?? "";

    check(Boolean(nonce), `${path}: la CSP no trae nonce`);
    if (nonce) nonces.add(nonce);
    check(!/'unsafe-inline'|'unsafe-eval'/.test(script), `${path}: script-src permite unsafe-inline o unsafe-eval`);
    check(/'strict-dynamic'/.test(script), `${path}: falta 'strict-dynamic'`);
    for (const d of ["object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'"]) {
      check(csp.includes(d), `${path}: falta "${d}" en la CSP`);
    }
    check(/connect-src 'self' http/.test(csp), `${path}: connect-src no incluye la API`);
    // Cada <script> de la página lleva el nonce de ESA respuesta (si no, el navegador lo bloquearía).
    const tags = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
    check(tags.length > 0, `${path}: la página no trae scripts`);
    for (const tag of tags) check(!nonce || tag.includes(`nonce="${nonce}"`), `${path}: script sin el nonce: ${tag.slice(0, 80)}`);

    const h = (name) => res.headers.get(name);
    check(h("x-content-type-options") === "nosniff", `${path}: falta X-Content-Type-Options: nosniff`);
    check(h("x-frame-options") === "DENY", `${path}: falta X-Frame-Options: DENY`);
    check(h("referrer-policy") === "no-referrer", `${path}: falta Referrer-Policy`);
    check(Boolean(h("permissions-policy")), `${path}: falta Permissions-Policy`);
    check(Boolean(h("strict-transport-security")), `${path}: falta Strict-Transport-Security`);
    check(h("cross-origin-opener-policy") === "same-origin", `${path}: falta Cross-Origin-Opener-Policy`);
    check(h("x-powered-by") === null, `${path}: anuncia X-Powered-By`);
  }
  check(nonces.size === 3, `el nonce se repite entre pedidos (${nonces.size} distintos de 3)`);
} catch (error) {
  failures.push(String(error));
} finally {
  server.kill("SIGKILL");
}

if (failures.length) {
  console.error("\nFALLÓ la comprobación de cabeceras:\n- " + failures.join("\n- "));
  process.exit(1);
}
console.log("\nCabeceras de seguridad y CSP con nonce: todo en orden.");
process.exit(0);
