// Gate browser probe for the Phase 4a rows U15 (`ui`) and U7 (`explore_panels`):
// Home, a dashboard and Explore with a Loki query + Live tail in container
// Chromium, counting CSP violations, page errors, failed requests, HTTP >= 400
// and WebSocket upgrades.
//
// PROVENANCE: verbatim port of harness/phase4/live4a/scripts/ui15.mjs (t-live4a),
// the script whose runs are the walk observations for these probes: Viewer run
// logs/146 (p4v, krate-overview: 0 CSP, 0 page errors, live/ws frames on every
// page, the only >=400 the UI's own public-dashboards 404, Explore redirected
// to Home by stock Grafana RBAC — `Access denied … action:datasources:explore`,
// logs/147) and Admin run logs/148 (p4both, dashboard p4lokiui: 2669 log rows,
// 0 panel-error icons, Explore 261 rows, Live tail 301 rows over the
// /loki/api/v1/tail WebSocket with frames). Only the header, the HOST default
// and this comment differ from the walked file.
//
// Runs in krate-harness/playwright:1.60.0 with --host-resolver-rules (the gate's
// name-mapping shape). Secrets from the environment only: UI15_PASSWORD,
// UI15_TOTP (base32, as keycloak_login_flow.py enrol writes it). Nothing secret
// is printed. Output: one JSON `step` line per stage, then `SUMMARY <json>`;
// ui15-summary.json + PNGs land in --out.
//   node phase4-browser.mjs --base https://HOST:PORT --host HOST --resolve-to IP --out /out
import { createRequire } from 'node:module';
const require = createRequire(process.env.PW_MODULES ? process.env.PW_MODULES + '/x.js' : import.meta.url);
const { chromium } = require('playwright');
import { createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, arr) => {
  if (v.startsWith('--')) a.push([v.slice(2), arr[i + 1]]);
  return a;
}, []));
const HOST = args.host || 'localhost';
const BASE = (args.base || `https://${HOST}`).replace(/\/$/, '');
const OUT = args.out || '/out';
const G = `${BASE}/grafana`;
const USER = process.env.UI15_USER || 'p4v';
const DASH = process.env.UI15_DASH || 'krate-overview';
const PW = process.env.UI15_PASSWORD;
const TOTP_B32 = process.env.UI15_TOTP;
const resolveTo = args['resolve-to'];
if (!PW || !TOTP_B32) { console.error('need UI15_PASSWORD and UI15_TOTP in the environment'); process.exit(2); }

function b32bytes(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0; const out = [];
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const i = A.indexOf(ch); if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp() {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const d = createHmac('sha1', b32bytes(TOTP_B32)).update(counter).digest();
  const o = d[d.length - 1] & 15;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

const result = { steps: [], console: [], pageErrors: [], csp: [], failed: [], websockets: [], http4xx5xx: [] };
const step = (name, data) => { const s = { t: new Date().toISOString(), name, ...data }; result.steps.push(s); console.log(JSON.stringify(s)); };

let n = 0;
async function shot(page, slug) { n += 1; const f = `${String(n).padStart(2, '0')}-${slug}.png`; await page.screenshot({ path: `${OUT}/${f}` }); return f; }

const browser = await chromium.launch({ args: resolveTo ? [`--host-resolver-rules=MAP ${HOST} ${resolveTo}`] : [] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
page.on('console', m => {
  const e = { type: m.type(), text: m.text().slice(0, 300), url: page.url().replace(BASE, '') };
  if (/Content Security Policy|Refused to/i.test(m.text())) result.csp.push(e);
  if (m.type() === 'error' || m.type() === 'warning') result.console.push(e);
});
page.on('pageerror', e => result.pageErrors.push({ text: String(e).slice(0, 300), url: page.url().replace(BASE, '') }));
page.on('requestfailed', r => result.failed.push({ url: r.url().replace(BASE, '').split('?')[0], err: r.failure()?.errorText }));
page.on('response', r => { if (r.status() >= 400 && r.url().startsWith(BASE)) result.http4xx5xx.push({ s: r.status(), m: r.request().method(), url: r.url().replace(BASE, '').split('?')[0] }); });
page.on('websocket', ws => {
  const w = { url: ws.url().replace(BASE.replace('https', 'wss'), ''), framesIn: 0, framesOut: 0, error: null };
  result.websockets.push(w);
  ws.on('framereceived', () => { w.framesIn += 1; });
  ws.on('framesent', () => { w.framesOut += 1; });
  ws.on('socketerror', e => { w.error = String(e); });
});

try {
  await page.goto(`${G}/`, { waitUntil: 'networkidle' });
  await page.getByRole('link', { name: /Krate sign-in/ }).first().click();
  await page.waitForSelector('#username', { timeout: 30000 });
  await page.fill('#username', USER); await page.fill('#password', PW); await page.click('#kc-login');
  await page.waitForSelector('#otp', { timeout: 30000 });
  await page.fill('#otp', totp()); await page.click('#kc-login');
  await page.waitForURL(u => u.toString().startsWith(`${G}/`) && !u.toString().includes('/login'), { timeout: 30000 });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(4000);
  step('home loaded', { url: page.url().replace(BASE, ''), shot: await shot(page, 'home') });

  await page.goto(`${G}/d/${DASH}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(7000);
  step('dashboard loaded', {
    dash: DASH, url: page.url().replace(BASE, ''),
    panelErrorIcons: await page.locator('[data-testid*="Panel status error"], [data-testid*="panel status error"]').count(),
    logRows: await page.locator('[class*="logs-row"], [data-testid*="logRows"] tr, table tr').count(),
    shot: await shot(page, 'dashboard') });

  const panes = { l: { datasource: 'loki', queries: [{ refId: 'A', expr: '{job="containerlogs"}', queryType: 'range', datasource: { type: 'loki', uid: 'loki' } }], range: { from: 'now-5m', to: 'now' } } };
  await page.goto(`${G}/explore?schemaVersion=1&panes=${encodeURIComponent(JSON.stringify(panes))}&orgId=1`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(6000);
  step('explore loki loaded', {
    url: page.url().replace(BASE, ''),
    logRows: await page.locator('[class*="logs-row"], [data-testid*="logRows"] tr, table tr').count(),
    shot: await shot(page, 'explore') });
  await page.getByRole('button', { name: /^Live$/ }).first().click();
  await page.waitForTimeout(20000);
  step('explore live tail 20 s', {
    liveRows: await page.locator('[class*="logs-row"], [data-testid="logRows"] tr').count(),
    websockets: result.websockets, shot: await shot(page, 'explore-live') });
} catch (e) {
  step('probe ended', { error: String(e.message || e).slice(0, 300) });
}
const summary = {
  cspViolations: result.csp.length,
  pageErrors: result.pageErrors.length,
  failedRequests: result.failed,
  http4xx5xx: result.http4xx5xx,
  websockets: result.websockets,
  consoleErrors: result.console.filter(c => c.type === 'error'),
};
writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, ...summary }, null, 2));
console.log('SUMMARY ' + JSON.stringify(summary));
await browser.close();
