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
let page = null;
let served_from = null;
const serve = MAC ? attachServeTracker(null) : null;
const ext = MAC ? externalAttemptsTracker(HOST) : null;
const failures = [];
function recordFailure(stage, error) {
  const message = String(error?.message || error).slice(0, 300);
  failures.push({ stage, error: message });
  process.exitCode = 1;
  console.error(`STORY FAILED: ${stage}: ${message}`);
  step(stage, { error: message });
}

// Once the browser has launched, every setup, probe and assertion failure must
// reach live evidence collection and teardown; none may exit the process early.
try {
  const context = MAC ? browser : await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
  page = MAC ? (context.pages()[0] || await context.newPage()) : await context.newPage();
  // Review T07: the external-request guard and the served-response tracker are installed BEFORE the first navigation (the
  // certificate acceptance below is already a page load), context-wide so every later page is covered too.
  if (MAC) { await ext.guard(context); serve.attachContext(context); }
  if (MAC) {
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
    page = context.pages()[0] || await context.newPage();
  }
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
  // Walk log 147 (Viewer p4v): stock Grafana RBAC has no datasources:explore for the
  // Viewer, so Grafana 302s Explore to Home — the `ui` row (phase4_grafana.py)
  // documents that redirect as stock behavior, not a story failure. Only the Admin
  // run (U7) reaches a Live tail. Clicking Live on the redirected Home page would
  // time out and fail the whole story (the strict T20 propagation), so the Live step
  // is conditional on where the browser actually is after the explore navigation.
  const exploreUrl = page.url().replace(BASE, '').split(/[?#]/)[0];
  if (exploreUrl.startsWith('/grafana/explore')) {
    await page.getByRole('button', { name: /^Live$/ }).first().click();
    await page.waitForTimeout(20000);
    step('explore live tail 20 s', {
      liveRows: await page.locator('[class*="logs-row"], [data-testid="logRows"] tr').count(),
      websockets: result.websockets, shot: await shot(page, 'explore-live') });
  } else if (exploreUrl === '/grafana/' || exploreUrl === '/grafana') {
    await page.waitForTimeout(20000);   // the same 20 s dwell so WebSocket activity still accumulates
    step('explore redirected (stock viewer RBAC)', {
      url: exploreUrl, websockets: result.websockets, shot: await shot(page, 'explore-redirected') });
  } else {
    // The stock RBAC redirect lands on Home exactly (walk log 147: "/grafana/"). Any other
    // destination — a Grafana login page, the IdP login, an error page — is an
    // authentication regression wearing the redirect's clothes; it must fail the story,
    // not pass it as the Viewer shape.
    throw new Error(`explore redirected to "${exploreUrl}", not the Viewer's stock Home (an authentication regression, not stock RBAC)`);
  }
  // Both vantage assertions and the external-attempt assertion share the failure path.
  if (MAC) {
    const mr = serve.last();
    if (!mr) throw new Error('no main-document response captured for the vantage assertion');
    served_from = (await assertServedFrom(mr, resolveTo, 'main document')) + '; ' + (await assertServedCertificate(mr, PIN, 'main document'));
    step('vantage evidence', { served_from });
    await ext.assertClean();
  }
} catch (e) {
  recordFailure('probe ended', e);
} finally {
  // Read the live page before closing it, even when a vantage assertion failed.
  let browserReceipt = null;
  let evidenceFailed = null;
  try {
    browserReceipt = await browserEvidence({ browser, mode: launch.mode, rules: launch.rules, headless: launch.headless, page, cert: PIN, extra: { story: 'U15/U7 phase4-browser', servedFrom: served_from } });
  } catch (e) {
    evidenceFailed = String(e.message || e).slice(0, 300);
    recordFailure('browser evidence failed', e);
  }
  try {
    if (ext) await ext.closeOwnedBrowser(() => browser.close());
    else await browser.close();
  } catch (e) {
    recordFailure('browser cleanup failed', e);
  }
  if (MAC) {
    try {
      const keep = failures.length > 0;
      const removed = cleanProfile(launch.profileDir, keep);
      if (!keep && launch.profileDir && !removed) recordFailure('profile cleanup failed', new Error('story profile could not be removed'));
    } catch (e) {
      recordFailure('profile cleanup failed', e);
    }
  }
  // Persist after teardown so cleanup failures are in the receipts as well.
  // An unavailable live capture is explicit; it is never substituted by invented proof.
  try {
    writeFileSync(`${OUT}/browser.json`, JSON.stringify({ ...(browserReceipt || { story: 'U15/U7 phase4-browser', evidenceFailed }), networkGuard: ext ? ext.evidence() : null, failures }, null, 2));
    chmodSync(`${OUT}/browser.json`, 0o644);
  } catch (e) {
    recordFailure('browser.json not written', e);
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
    networkGuard: ext ? ext.evidence() : null,
    storyFailed: failures[0]?.error || null,
    failures,
  };
  try {
    writeFileSync(`${OUT}/ui15-summary.json`, JSON.stringify({ steps: result.steps, ...summary }, null, 2));
  } catch (e) {
    recordFailure('ui15-summary.json not written', e);
  }
  // Include a summary-write failure in stdout even when the file cannot be saved.
  console.log('SUMMARY ' + JSON.stringify({ ...summary, storyFailed: failures[0]?.error || null }));
}
