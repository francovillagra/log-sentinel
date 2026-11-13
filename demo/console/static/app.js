"use strict";

// Todo lo que viene del servidor se escribe con textContent: nada se interpreta como HTML.

const $ = (selector) => document.querySelector(selector);
const POLL_MS = 500;
const STATUS_MS = 4000;

const state = { lastEvent: 0, hiddenBefore: 0, polling: false, password: "", passwordShown: false, rendered: false };

try {
  state.hiddenBefore = Number(sessionStorage.getItem("hiddenBefore")) || 0;
} catch {
  // sin almacenamiento del navegador: la lista simplemente no recuerda lo que se vació
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : String(value));
  }
  node.append(...children);
  return node;
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(String(response.status));
  return response.json();
}

// ---- estado general y acceso al panel ------------------------------------------------------------------------------

function setStatus(kind, text) {
  const node = $("#status");
  node.dataset.state = kind;
  node.textContent = text;
}

function isLocalUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

function showAccess(info) {
  if (isLocalUrl(info.panel_url)) $("#panel-link").href = info.panel_url;
  const creds = $("#creds");
  if (!info.login) {
    creds.hidden = true;
    return;
  }
  state.password = info.login.password;
  $("#cred-email").textContent = info.login.email;
  paintPassword();
  creds.hidden = false;
}

function paintPassword() {
  $("#cred-pass").textContent = state.passwordShown ? state.password : "•".repeat(12);
  $("#toggle-pass").textContent = state.passwordShown ? "Ocultar" : "Mostrar";
}

async function refresh() {
  try {
    const info = await getJson("/api/state");
    if (!state.rendered) renderScenarios(info.scenarios);
    showAccess(info);
    if (info.api_ready) setStatus("ok", "Sistema listo");
    else setStatus("wait", "Esperando que el sistema termine de arrancar…");
  } catch {
    setStatus("error", "No se puede hablar con la consola");
  }
}

// ---- botones de las pruebas ----------------------------------------------------------------------------------------

function renderScenarios(scenarios) {
  const list = $("#scenarios");
  list.replaceChildren(
    ...scenarios.map((scenario) =>
      el("li", { class: "card", "data-kind": scenario.kind },
        el("h3", { text: scenario.title }),
        el("p", { text: scenario.story }),
        el("button", { type: "button", class: "btn", "data-id": scenario.id, text: "Probar" }),
      ),
    ),
  );
  state.rendered = true;
  // Si la página se recargó con una prueba en curso, los botones esperan a que termine.
  if (state.polling) for (const button of list.querySelectorAll("button")) button.disabled = true;
}

function setBusy(busy, active) {
  for (const button of document.querySelectorAll("#scenarios button")) {
    button.disabled = busy;
    if (!busy) button.textContent = "Probar";
  }
  if (busy && active) active.textContent = "Enviando…";
}

async function run(id, button) {
  setBusy(true, button);
  let response;
  try {
    response = await fetch(`/api/run/${encodeURIComponent(id)}`, { method: "POST" });
  } catch {
    setBusy(false);
    setStatus("error", "No se puede hablar con la consola");
    return;
  }
  if (response.status !== 202 && response.status !== 409) {
    setBusy(false);
    return;
  }
  poll();
}

async function poll() {
  if (state.polling) return;
  state.polling = true;
  try {
    for (;;) {
      const { events, running } = await getJson(`/api/events?since=${state.lastEvent}`);
      for (const event of events) addEvent(event);
      if (!running) break;
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
  } catch {
    setStatus("error", "Se perdió la conexión con la consola");
  } finally {
    state.polling = false;
    setBusy(false);
  }
}

// ---- lo que va pasando ---------------------------------------------------------------------------------------------

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function addEvent(event) {
  state.lastEvent = Math.max(state.lastEvent, event.n);
  if (event.n <= state.hiddenBefore) return;

  const status = event.error ? "error" : event.ok ? "ok" : "miss";
  const expectsAlerts = event.expect.length > 0;   // el tráfico normal es el único que no debe disparar nada
  const verdict = {
    error: "No se pudo enviar",
    miss: expectsAlerts ? "No se detectó" : "Avisó de más",
    ok: expectsAlerts ? "Detectado" : "Sin alertas, como corresponde",
  }[status];

  const title = event.steps > 1 ? `${event.title}: etapa ${event.step} de ${event.steps}` : event.title;
  const when = new Date(event.t).toLocaleTimeString("es-AR", { hour12: false });

  const entry = el("li", { class: "entry", "data-status": status },
    el("div", { class: "entry-top" },
      el("span", { class: "time mono", text: when }),
      el("span", { class: "entry-title", text: title }),
      el("span", { class: "verdict", "data-status": status, text: verdict }),
    ),
    el("p", { class: "sent" },
      `${event.what}`,
      ...(event.ip ? [" (desde ", el("span", { class: "mono", text: event.ip }), ")"] : []),
    ),
  );

  if (event.error) {
    entry.append(el("p", { class: "error-text", text: event.error }));
  } else if (event.alerts.length > 0) {
    entry.append(
      el("ul", { class: "found" },
        ...event.alerts.map((alert) =>
          el("li", {},
            el("span", { class: "sev", "data-sev": alert.severity, text: `Severidad ${alert.severity_label}` }),
            el("span", { text: alert.label }),
            el("span", { class: "evidence mono", title: alert.evidence, text: alert.evidence }),
          ),
        ),
      ),
    );
  }

  if (event.lines.length > 0) {
    const shown = event.lines.join("\n") + (event.more_lines > 0 ? `\n… y ${event.more_lines} líneas más` : "");
    entry.append(
      el("details", {},
        el("summary", { text: `Ver lo que se envió (${event.sent} ${event.sent === 1 ? "línea" : "líneas"} de log)` }),
        el("pre", { text: shown }),
      ),
    );
  }

  $("#log .empty")?.remove();
  $("#log").prepend(entry);
}

function clearLog() {
  state.hiddenBefore = state.lastEvent;
  try {
    sessionStorage.setItem("hiddenBefore", String(state.hiddenBefore));
  } catch {
    // ver arriba
  }
  $("#log").replaceChildren(el("li", { class: "empty", text: "Lista vaciada. Elegir una prueba." }));
}

// ---- arranque --------------------------------------------------------------------------------------------------------

$("#scenarios").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-id]");
  if (button && !button.disabled) run(button.dataset.id, button);
});
$("#clear").addEventListener("click", clearLog);
$("#toggle-pass").addEventListener("click", () => {
  state.passwordShown = !state.passwordShown;
  paintPassword();
});
$("#copy-pass").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  try {
    await navigator.clipboard.writeText(state.password);
    button.textContent = "Copiada";
  } catch {
    state.passwordShown = true; // sin portapapeles: se muestra para copiarla a mano
    paintPassword();
    button.textContent = "Copiar a mano";
  }
  setTimeout(() => { button.textContent = "Copiar"; }, 1800);
});

refresh();
setInterval(refresh, STATUS_MS);
// Si se recarga la página con una prueba en curso (o con avisos anteriores), se retoma desde el servidor.
poll();
