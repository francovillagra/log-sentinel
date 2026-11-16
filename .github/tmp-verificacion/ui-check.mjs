// Recorrido en el navegador de la demo de Log-Sentinel (verificación temporal): la consola de práctica manda tráfico de ataque y el panel de
// avisos debe mostrar las alertas. Usa el Google Chrome que ya trae el servidor de GitHub. Termina con código 1 si algo no da lo esperado.
// Las credenciales de práctica (generadas por la demo en este servidor) se leen de la consola y se usan solo para entrar al panel: no se imprimen.
import { chromium } from 'playwright-core';
import { appendFileSync } from 'node:fs';

const CONSOLE = 'http://127.0.0.1:4000';
const PANEL = 'http://127.0.0.1:4001';
const RULES = ['brute_force', 'sqli', 'xss', 'path_traversal', 'suspicious_ua', 'rate_anomaly'];
const lines = [];
let failed = 0;
const check = (ok, text) => {
  const line = `${ok ? 'OK   ' : 'FALLA'} ${text}`;
  lines.push(line);
  console.log(line);
  if (!ok) failed += 1;
};
const escape = (text) => text.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');

const browser = await chromium.launch({ channel: 'chrome' });
try {
  const problems = [];
  const watch = (page, label) => {
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`${label} consola: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`${label} excepción: ${e.message}`));
    page.on('requestfailed', (r) => problems.push(`${label} pedido fallido: ${r.url()}`));
  };

  // ---- Consola de práctica ----
  const consolePage = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  watch(consolePage, 'consola');
  await consolePage.goto(CONSOLE, { waitUntil: 'domcontentloaded' });
  await consolePage.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  check((await consolePage.locator('#status').innerText()).includes('Sistema listo'), 'consola: arriba dice «Sistema listo»');

  // ---- Panel de avisos: se entra con la cuenta de práctica que muestra la consola ----
  await consolePage.locator('#creds').waitFor({ state: 'visible', timeout: 30_000 });
  await consolePage.locator('#toggle-pass').click();
  const email = (await consolePage.locator('#cred-email').innerText()).trim();
  const password = (await consolePage.locator('#cred-pass').innerText()).trim();
  check(email.length > 0 && password.length >= 12 && !password.includes('•'), 'consola: muestra usuario y contraseña de práctica (no se imprimen)');

  const panel = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  watch(panel, 'panel');
  await panel.goto(`${PANEL}/login`, { waitUntil: 'domcontentloaded' });
  await panel.locator('#email').fill(email);
  await panel.locator('#password').fill(password);
  await panel.getByRole('button', { name: 'Ingresar' }).click();
  try {
    await panel.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 60_000 });
    check(true, 'panel: el login con la cuenta de práctica entra al tablero');
  } catch {
    check(false, `panel: el login no entró al tablero (sigue en ${new URL(panel.url()).pathname})`);
  }

  // ---- Las ocho pruebas de la consola ----
  const cards = consolePage.locator('#scenarios li.card');
  const count = await cards.count();
  check(count === 8, `consola: ${count} pruebas disponibles (esperadas 8)`);
  for (let i = 0; i < count; i += 1) {
    const card = cards.nth(i);
    const title = (await card.locator('h3, .name, strong').first().innerText().catch(() => `prueba ${i + 1}`)).trim();
    try {
      await card.getByRole('button', { name: 'Probar' }).click({ timeout: 60_000 });
      await consolePage.waitForFunction(
        () => [...document.querySelectorAll('#scenarios button')].every((b) => !b.disabled && b.textContent.trim() === 'Probar'),
        undefined,
        { timeout: 180_000 },
      );
      check(true, `consola: «${title}» terminó de enviarse`);
    } catch (error) {
      check(false, `consola: «${title}» no terminó: ${String(error.message).split('\n')[0]}`);
    }
  }

  const verdicts = await consolePage.locator('#log .entry').evaluateAll((nodes) => nodes.map((n) => ({
    status: n.getAttribute('data-status'),
    verdict: n.querySelector('.verdict')?.textContent.trim() ?? '',
  })));
  const bad = verdicts.filter((v) => v.status !== 'ok');
  check(verdicts.length >= 8 && bad.length === 0, `consola: ${verdicts.length} envíos, todos con el veredicto esperado (fuera de lo esperado: ${bad.length}${bad.length ? ' → ' + bad.map((b) => b.verdict).join(', ') : ''})`);
  const detected = verdicts.filter((v) => v.verdict === 'Detectado').length;
  const normal = verdicts.filter((v) => v.verdict === 'Sin alertas, como corresponde').length;
  check(detected >= 7 && normal === 1, `consola: ${detected} envíos «Detectado» y ${normal} «Sin alertas, como corresponde» (esperado: al menos 7 y exactamente 1)`);
  await consolePage.screenshot({ path: 'consola.png', fullPage: true });

  // ---- El panel debe mostrar las seis reglas en vivo ----
  for (const rule of RULES) {
    try {
      await panel.getByText(rule, { exact: false }).first().waitFor({ state: 'visible', timeout: 30_000 });
      check(true, `panel: muestra una alerta de la regla ${rule}`);
    } catch {
      check(false, `panel: no mostró ninguna alerta de la regla ${rule}`);
    }
  }
  await panel.screenshot({ path: 'panel.png', fullPage: true });

  // ---- Celular ----
  const phone = await (await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })).newPage();
  watch(phone, 'celular');
  await phone.goto(CONSOLE, { waitUntil: 'domcontentloaded' });
  await phone.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(overflow <= 1, `celular: la consola no se desborda (sobran ${overflow} px)`);
  await phone.screenshot({ path: 'celular.png', fullPage: true });

  check(problems.length === 0, `sin errores en la consola del navegador (${problems.length})${problems.length ? ': ' + problems.slice(0, 3).join(' | ') : ''}`);
} finally {
  await browser.close();
}

const ok = lines.length - failed;
const summary = `Recorrido en el navegador: ${ok} de ${lines.length} comprobaciones en orden`;
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Recorrido en el navegador\n\n\`\`\`\n${lines.join('\n')}\n\`\`\`\n\n`);
if (failed) {
  console.log(`::error title=Recorrido en el navegador::${escape([summary, '', ...lines.filter((l) => l.startsWith('FALLA'))].join('\n'))}`);
  process.exit(1);
}
console.log(`::notice title=Recorrido en el navegador::${escape([summary, '', ...lines].join('\n'))}`);
