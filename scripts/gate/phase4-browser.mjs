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
//
// Mac vantage (GATE_BROWSER_MAC=1, scripts/gate/browser-launch.mjs): exactly the shape walked
// on 2026-10-17 with the m5/phase4-browser.m5.mjs adapter (launch block + interstitial block
// ONLY, per that file's header) — installed headed Chrome, fresh profile
// `--host-resolver-rules=MAP <host> <ip>, MAP * ~NOTFOUND, EXCLUDE <ip>`, ignoreHTTPSErrors
// NOT set, Advanced+Proceed on the real interstitial, then the same walk. Added in the Mac
// vantage (encoded from the same walk plus TOPOFIX-REVIEW F2/F3): served_from (Response
// .serverAddr/securityDetails vs the pinned certificate, M0 point 4), external_attempts
// (`requestfailed` of a non-gate host; the fingerprint of a violation is
// net::ERR_NAME_NOT_RESOLVED, M5 run 3), browser.json, the Node certificate pin. M0 point 6:
// CDP Network.getCertificate is NOT a digest source in Chrome 155 — there is no CDP digest
// claim here.
import { createRequire } from 'node:module';
const require = createRequire(process.env.PW_MODULES ? process.env.PW_MODULES + '/x.js' : import.meta.url);
const { chromium } = require('playwright');
import { createHmac } from 'node:crypto';
import { writeFileSync, chmodSync } from 'node:fs';
import { macMode, launchGateBrowser, cleanProfile, requireCertFile, pinGateCertificate, attachServeTracker, browserEvidence, externalAttemptsTracker, assertServedFrom, assertServedCertificate, acceptGateCertificate } from './browser-launch.mjs';

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

// Mac vantage (launch lines only, per the m5 adapter which was walked exactly like this):
// the installed Chrome on the Mac with the M0 launch lines - headed, fresh profile, the
// fixture name mapped to the VM, every other name NOTFOUND so the browser cannot leave the
// machine. The fixture certificate is not trusted by the Mac keychain, so the first
// navigation shows the real interstitial; the probe proceeds after the human-style Advanced +
// Proceed below (M0 point 3: one exception covers the same host+port). ignoreHTTPSErrors
// deliberately NOT set. The certificate is pinned first (Node, name check on, M4); the served
// certificate and server address are asserted at summary time.
const MAC = macMode();
const CERT = MAC ? requireCertFile() : null;
const PORT_FOR_PIN = (new URL(BASE).port ? Number(new URL(BASE).port) : 443);
const PIN = MAC ? await pinGateCertificate({ host: HOST, port: PORT_FOR_PIN, certPem: CERT.pem, connectHost: resolveTo }) : null;
const launch = await launchGateBrowser(chromium, { host: HOST, resolveTo, outDir: OUT });
const browser = launch.browser;
const context = MAC ? browser : await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
let page = MAC ? (context.pages()[0] || await context.newPage()) : await context.newPage();
if (MAC) {
  // Review N3: U15's interstitial handling is the shared acceptGateCertificate path (the same
  // selectors, the same order the other three stories use: waitForSelector before the count
  // check, the hooks before the strict F2 throw), and a stopped story CLOSES the headed
  // browser instead of a bare process.exit leaving it on screen.
  try {
    const accepted = await acceptGateCertificate(page, `${BASE}/`, {
      onAssert: (d) => {
        result.steps.push({ t: new Date().toISOString(), name: d.seen ? 'interstitial' : 'no-interstitial', error: d.error, url: page.url().replace(BASE, '').split(/[?#]/)[0] });
        if (!/ERR_CERT_AUTHORITY_INVALID/.test(d.error || '')) {
          result.steps.push({ t: new Date().toISOString(), name: 'interstitial-unexpected', error: d.error });
        }
      },
      onShot: async () => { await page.screenshot({ path: `${OUT}/interstitial.png` }).catch(() => {}); },
    });
    // acceptGateCertificate runs the hooks only when the interstitial is seen, so a missing
    // interstitial returns here with decision 'no-interstitial': stop as X1/X3/X4 do (TR2 G1).
    if (accepted.decision !== 'proceed') {
      result.steps.push({ t: new Date().toISOString(), name: 'no-interstitial', error: accepted.error });
      throw new Error('the trust-nothing Mac profile showed no interstitial (a pre-trusted or reused profile)');
    }
    console.log(JSON.stringify({ t: new Date().toISOString(), name: 'proceeded' }));
  } catch (e) {
    console.error('STORY FAILED: ' + String(e.message || e).slice(0, 200));
    // G7: persist the steps (the no-interstitial step included) before the non-zero exit; the runner reads them from ui15-summary.json
    try { writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, storyFailed: String(e.message || e).slice(0, 200) }, null, 2)); } catch { /* the STORY FAILED line above remains */ }
    await browser.close().catch(() => {});
    cleanProfile(launch.profileDir, true);
    process.exit(2);
  }
  page = context.pages()[0] || await context.newPage();
}
const serve = MAC ? attachServeTracker(null) : null;  // attached to the fresh page below
const ext = MAC ? externalAttemptsTracker(HOST) : null;
if (MAC) { serve.attach(page); ext.attach(page); }
page.on('console', m => {
  const e = { type: m.type(), text: m.text().slice(0, 300), url: page.url().replace(BASE, '').split(/[?#]/)[0] };
  if (/Content Security Policy|Refused to/i.test(m.text())) result.csp.push(e);
  if (m.type() === 'error' || m.type() === 'warning') result.console.push(e);
});
page.on('pageerror', e => result.pageErrors.push({ text: String(e).slice(0, 300), url: page.url().replace(BASE, '').split(/[?#]/)[0] }));
page.on('requestfailed', r => result.failed.push({ url: r.url().replace(BASE, '').split(/[?#]/)[0], err: r.failure()?.errorText }));
page.on('response', r => { if (r.status() >= 400 && r.url().startsWith(BASE)) result.http4xx5xx.push({ s: r.status(), m: r.request().method(), url: r.url().replace(BASE, '').split(/[?#]/)[0] }); });
page.on('websocket', ws => {
  const w = { url: ws.url().replace(BASE.replace('https', 'wss'), '').split(/[?#]/)[0], framesIn: 0, framesOut: 0, error: null };
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
  step('home loaded', { url: page.url().replace(BASE, '').split(/[?#]/)[0], shot: await shot(page, 'home') });

  await page.goto(`${G}/d/${DASH}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(7000);
  step('dashboard loaded', {
    dash: DASH, url: page.url().replace(BASE, '').split(/[?#]/)[0],
    panelErrorIcons: await page.locator('[data-testid*="Panel status error"], [data-testid*="panel status error"]').count(),
    logRows: await page.locator('[class*="logs-row"], [data-testid*="logRows"] tr, table tr').count(),
    shot: await shot(page, 'dashboard') });

  const panes = { l: { datasource: 'loki', queries: [{ refId: 'A', expr: '{job="containerlogs"}', queryType: 'range', datasource: { type: 'loki', uid: 'loki' } }], range: { from: 'now-5m', to: 'now' } } };
  await page.goto(`${G}/explore?schemaVersion=1&panes=${encodeURIComponent(JSON.stringify(panes))}&orgId=1`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(6000);
  step('explore loki loaded', {
    url: page.url().replace(BASE, '').split(/[?#]/)[0],
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
// Mac vantage summary evidence (TOPOFIX-DESIGN 3.7): served_from from the main-document
// response, external attempts collected; both fail the probe when wrong.
let served_from = null;
if (MAC) {
  const mr = serve.last();
  if (!mr) {
    console.error('STORY FAILED: no main-document response captured for the vantage assertion');
    process.exitCode = 1;
    step('vantage missing', { error: 'no main-document response captured' });
  } else {
    served_from = (await assertServedFrom(mr, resolveTo, 'main document')) + '; ' + (await assertServedCertificate(mr, PIN, 'main document'));
    step('vantage evidence', { served_from });
    ext.assertClean();
  }
}
const summary = {
  cspViolations: result.csp.length,
  pageErrors: result.pageErrors.length,
  failedRequests: result.failed,
  http4xx5xx: result.http4xx5xx,
  websockets: result.websockets,
  consoleErrors: result.console.filter(c => c.type === 'error'),
  servedFrom: served_from,
  externalAttempts: MAC && ext ? ext.list : null,
};
writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, ...summary }, null, 2));
console.log('SUMMARY ' + JSON.stringify(summary));
try {
  const ev = await browserEvidence({ browser, mode: launch.mode, rules: launch.rules, headless: launch.headless, page, cert: PIN, extra: { story: 'U15/U7 phase4-browser', servedFrom: served_from } });
  writeFileSync(`${OUT}/browser.json`, JSON.stringify(ev, null, 2));
  chmodSync(`${OUT}/browser.json`, 0o644);
} catch (e2) { console.error('browser.json not written: ' + String(e2.message || e2).slice(0, 160)); }
await browser.close();
if (MAC) cleanProfile(launch.profileDir, process.exitCode === 1);
