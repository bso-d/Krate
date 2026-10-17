// End-user screenshot story for the identity gate, Phase 4a Grafana (row X3).
// STATUS: LIVE-VERIFIED AND WIRED as runner-owned X3 in gate-identity.sh.
// The live 4a walk ran this story unmodified in container Chromium: see
// harness/phase4/live4a/results.md (X3) and logs/143-144 for 12 assertions,
// five screenshots and a verified manifest. NEEDS-LIVE-VERIFICATION comments
// below are historical markers for selectors verified by that walk.
//
// Runs inside the harness Playwright container (krate-harness/playwright:1.60.0),
// the same image and invocation shape as screenshots.mjs (X1, unchanged):
// `--resolve-to IP` maps the public host (`--host NAME`, default localhost) to the
// Docker host gateway inside Chromium (--host-resolver-rules), so https://NAME[:port]
// reaches the published proxy port exactly as an end user's browser on the host does.
//
//   node screenshots-grafana.mjs --base https://krate-gate.test --host krate-gate.test \
//        --out /out/grafana --viewer-user V --admin-user A --resolve-to 192.168.65.254
// Credentials come from the environment only: GATE_VIEWER_PASSWORD, GATE_VIEWER_TOTP
// (base32, as keycloak_login_flow.py enrol writes it), GATE_ADMIN_PASSWORD,
// GATE_ADMIN_TOTP. Both users must be enrolled (TOTP + password change completed).
// Nothing secret is printed or written.
//
// Story (X3: exactly 5 PNGs, own directory, own manifest.tsv with sha256; every
// shot is taken only after its DOM assertions passed — shot() refuses a capture
// with no preceding assertion):
//   1 the Grafana login page offering only "Krate sign-in"
//   2 the Keycloak password form of realm krate
//   3 the Viewer on the Kafka overview dashboard without "Edit"/"New" controls
//   4 the Admin on the same dashboard with "Edit"
//   5 after logout, the Keycloak password form (no confirmation page)
//   6 (Mac vantage only) the certificate interstitial before step 1
//
// Browser vantage (scripts/gate/browser-launch.mjs): with GATE_BROWSER_MAC unset this is the
// walked container story (live4a/ee173ac ran it unmodified); with GATE_BROWSER_MAC=1 it
// drives the installed, signed, headed Google Chrome on the Mac — fresh profile, the fixture
// certificate pinned through Node with the name check on, Chrome's own certificate
// interstitial with Advanced + Proceed (one decision covers the host for the whole story,
// M0 point 3), every shot's main document bound to the VM address and to the served
// certificate (Response.serverAddr/securityDetails, M0 point 4), `MAP * ~NOTFOUND` keeping
// the browser offline, external attempts collected and failing the story. 5 PNGs in the
// container vantage, 6 with the interstitial shot in the Mac vantage.
import { createRequire } from 'node:module';
// The harness image installs playwright globally; ESM ignores NODE_PATH, so resolve it explicitly.
const require = createRequire(process.env.PW_MODULES ? process.env.PW_MODULES + '/resolve-from-here.js' : import.meta.url);
const { chromium } = require('playwright');
import { createHmac, createHash } from 'node:crypto';
import { writeFileSync, readFileSync, chmodSync, mkdirSync } from 'node:fs';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, v, i, arr) => {
  if (v.startsWith('--')) acc.push([v.slice(2), arr[i + 1]]);
  return acc;
}, []));
const HOST = args.host || 'localhost';
const BASE = (args.base || `https://${HOST}`).replace(/\/$/, '');
const OUT = args.out || '/out';
const G = `${BASE}/grafana`;
const DASHBOARD = `${G}/d/krate-overview`; // monitoring/grafana/dashboards/kafka-overview.json (uid krate-overview)
const VIEWER = args['viewer-user'];
const ADMIN = args['admin-user'];
const VIEWER_PW = process.env.GATE_VIEWER_PASSWORD;
const VIEWER_TOTP = process.env.GATE_VIEWER_TOTP;
const ADMIN_PW = process.env.GATE_ADMIN_PASSWORD;
const ADMIN_TOTP = process.env.GATE_ADMIN_TOTP;
if (!VIEWER || !VIEWER_PW || !VIEWER_TOTP || !ADMIN || !ADMIN_PW || !ADMIN_TOTP) {
  console.error('need --viewer-user, --admin-user, GATE_VIEWER_PASSWORD, GATE_VIEWER_TOTP, GATE_ADMIN_PASSWORD and GATE_ADMIN_TOTP (base32, from keycloak_login_flow.py enrol)');
  process.exit(2);
}
const SHOTS_EXPECTED_MAC = 6; // +1: the certificate interstitial the trust-nothing Mac profile must show
const SHOTS_EXPECTED_CONTAINER = 5;

const asserted = [];
function assert(cond, what) { if (!cond) throw new Error('assert: ' + what); asserted.push(what); }

// base32 (RFC 4648, no padding) -> Buffer: the enrolment state file stores the TOTP seed as base32.
function base32ToBytes(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let value = 0; const out = [];
  for (const ch of s.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase()) {
    const idx = A.indexOf(ch);
    if (idx < 0) throw new Error('not a base32 character: ' + ch);
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secretB32, t = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(t / 30)));
  const d = createHmac('sha1', base32ToBytes(secretB32)).update(counter).digest();
  const o = d[d.length - 1] & 15;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// Manifests and step records are published evidence: keep only origin+path,
// never the query or fragment (authorization codes, state and nonce are
// transient credentials, not evidence).
function publicUrl(u) { try { const x = new URL(u); return x.origin + x.pathname; } catch { return String(u).split(/[?#]/)[0]; } }
let n = 0;
const manifest = [];
async function capture(page, slug, caption) {
  n += 1;
  // Mac vantage: bind the shot's main document to the VM address and the pinned certificate
  // (assertServedFrom/assertServedCertificate; the fields' behaviour observed in M0 point 4).
  if (MAC && serve) await serve.record(resolveTo, PIN, slug, asserted);
  const file = `${String(n).padStart(2, '0')}-${slug}.png`;
  await page.screenshot({ path: `${OUT}/${file}`, fullPage: false });
  const bytes = readFileSync(`${OUT}/${file}`);
  manifest.push({
    file, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length,
    caption, url: publicUrl(page.url()), asserted: asserted.splice(0),
  });
  console.log(`${file}\t${caption}`);
}
async function shot(page, slug, caption) {
  // X3 rule: every story shot is taken AFTER its DOM assertions passed — a capture
  // with no pending assertion is a bug in this story, not a screenshot.
  if (asserted.length === 0) throw new Error('shot without a preceding DOM assertion: ' + slug);
  await capture(page, slug, caption);
}
function writeManifest() {
  const tsv = ['file\tsha256\tbytes\tcaption\turl\tasserted',
    // A field never carries a tab or a line break (a failure caption can hold a multi-line error).
    ...manifest.map((m) => [m.file, m.sha256, m.bytes, m.caption, m.url, m.asserted.join(' | ')]
      .map((v) => String(v).replace(/[\t\r\n]+/g, ' ')).join('\t'))].join('\n');
  writeFileSync(`${OUT}/manifest.tsv`, tsv + '\n');
  chmodSync(`${OUT}/manifest.tsv`, 0o644);
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2)); // convenience copy; the runner asserts on manifest.tsv
  chmodSync(`${OUT}/manifest.json`, 0o644);
}

mkdirSync(OUT, { recursive: true });
const resolveTo = args['resolve-to'];
// The launch is shared with X1/X4/U15-U7 through browser-launch.mjs.
import { launchGateBrowser, macMode, acceptGateCertificate, attachServeTracker, browserEvidence, cleanProfile, requireCertFile, pinGateCertificate, externalAttemptsTracker } from './browser-launch.mjs';
const MAC = macMode();
const SHOTS_EXPECTED = MAC ? SHOTS_EXPECTED_MAC : SHOTS_EXPECTED_CONTAINER;
const CERT = MAC ? requireCertFile() : null;
const PIN = MAC ? await pinGateCertificate({ host: HOST, port: 443, certPem: CERT.pem, connectHost: resolveTo }) : null;
const launch = await launchGateBrowser(chromium, { host: HOST, resolveTo, outDir: OUT });
const browser = launch.browser;
let certDecision = null;

// Keycloak login (password + OTP), selectors live-verified in lab6 scripts/ui.mjs.
async function keycloakLogin(page, user, password, totpB32) {
  await page.waitForSelector('#username', { timeout: 30000 });
  await page.fill('#username', user);
  await page.fill('#password', password);
  await page.click('#kc-login');
  await page.waitForSelector('#otp', { timeout: 30000 });
  await page.fill('#otp', totp(totpB32));
  await page.click('#kc-login');
}

async function signedInDashboard(ctx, user, password, totpB32) {
  const page = await ctx.newPage();
  await page.goto(`${G}/`, { waitUntil: 'networkidle' });
  const signIn = page.getByRole('link', { name: /Krate sign-in/ });  // lab6-verified selector
  await signIn.first().click();
  await keycloakLogin(page, user, password, totpB32);
  await page.waitForURL((u) => u.toString().startsWith(`${G}/`) && !u.toString().includes('/login'), { timeout: 30000 });
  await page.waitForLoadState('networkidle');
  await page.goto(DASHBOARD, { waitUntil: 'networkidle' });
  await page.waitForTimeout(5000);
  return page;
}

let page = null;
// Mac vantage trackers: serve (per-shot main-document evidence) and ext (F3 external attempts).
const serve = MAC ? attachServeTracker(null) : null;
const ext = MAC ? externalAttemptsTracker(HOST) : null;
try {
  const ctx = MAC ? browser : await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
  page = MAC ? (ctx.pages()[0] || await ctx.newPage()) : await ctx.newPage();
  // Review T07/T21: the external-request guard and the served-response tracker are CONTEXT-wide and installed before the first
  // navigation, so the Admin page (created later by signedInDashboard) is covered from its first request.
  if (ext) { await ext.guard(ctx); serve.attachContext(ctx); }

  // ── Mac vantage gate: the trust-nothing profile must show and pass Chrome's own certificate
  // interstitial before story step 1 (M0 points 2-3; M5 run 2 for the render-after-reject
  // order; one Advanced+Proceed covers this host for the whole story). The code proves only
  // that the chain has no trusted root (F2); the pin above carries name/date validity.
  if (MAC) {
    const decision = await acceptGateCertificate(page, `${G}/`, {
      onAssert: (d) => {
        assert(d.seen, 'the trust-nothing profile saw Chrome\'s real certificate interstitial (none seen: a pre-trusted or reused profile)');
        assert(/ERR_CERT_AUTHORITY_INVALID/.test(d.error), `the interstitial carries net::ERR_CERT_AUTHORITY_INVALID (got: ${d.error || 'none'}; F2: the code ranks above name/date, so another code means another defect)`);
      },
      onShot: async () => { await shot(page, 'certificate-warning', 'Chrome shows its own certificate warning for the untrusted fixture certificate; name and date validity are evidenced by the Node pin and the securityDetails assertions, not by this code'); },
    });
    assert(decision.decision === 'proceed', 'the story proceeded through Advanced -> Proceed (one decision covers this host; got: ' + (decision.decision || 'none') + ')');
    certDecision = decision;
  }
  // ── shot 1: the Grafana login page offers only "Krate sign-in" ──
  await page.goto(`${G}/`, { waitUntil: 'networkidle' });
  const provider = page.getByRole('link', { name: /Krate sign-in/ });
  assert(await provider.count() === 1, `the login page offers exactly one provider link, "Krate sign-in" (found ${await provider.count()})`);
  assert((await page.locator('input[type=password]').count()) === 0, 'the login page has no password field (the built-in login form is off)');
  // NEEDS-LIVE-VERIFICATION: assert no other provider button exists (lab6 counted only
  // the one link; the walk notes must confirm no second sign-in option renders).
  await shot(page, 'grafana-login-page', 'Grafana over HTTPS at /grafana/: the login page offers only "Krate sign-in" (no Grafana password form)');

  // ── shot 2: the Keycloak password form of realm krate ──
  await provider.first().click();
  await page.waitForSelector('#kc-form-login', { timeout: 30000 });
  assert(page.url().includes('/identity/realms/krate/'), `the authorize redirect reached the realm krate (${page.url().split(/[?#]/)[0]})`);
  assert((await page.locator('#username').count()) === 1 && (await page.locator('#password').count()) === 1, 'the Keycloak password form is shown');
  await shot(page, 'keycloak-password-form', 'The Krate realm asks for the password (single sign-in authority for Grafana)');

  // ── shot 3: the Viewer on the Kafka overview dashboard, no Edit/New controls ──
  await keycloakLogin(page, VIEWER, VIEWER_PW, VIEWER_TOTP);
  await page.waitForURL((u) => u.toString().startsWith(`${G}/`) && !u.toString().includes('/login'), { timeout: 30000 });
  await page.waitForLoadState('networkidle');
  await page.goto(DASHBOARD, { waitUntil: 'networkidle' });
  await page.waitForTimeout(5000);
  assert(page.url().startsWith(DASHBOARD), `the Viewer landed on the provisioned overview dashboard (${page.url().split(/[?#]/)[0]})`);
  // NEEDS-LIVE-VERIFICATION: the exact absence selectors for the Viewer (Grafana 12.2
  // toolbar). Candidates to confirm in the walk: [aria-label="Edit dashboard"], the
  // header "Edit" button, and any "New"/add-panel control.
  assert((await page.locator('[aria-label="Edit dashboard"]').count()) === 0, 'the Viewer sees no "Edit dashboard" control');
  assert((await page.getByRole('button', { name: /^Edit$/ }).count()) === 0, 'the Viewer sees no "Edit" button');
  assert((await page.getByRole('button', { name: /^New$/ }).count()) === 0, 'the Viewer sees no "New" button');
  await shot(page, 'viewer-dashboard', `Viewer ${VIEWER} on the Kafka overview dashboard: read-only, no "Edit"/"New" controls`);
  await ctx.clearCookies();
  await page.close();

  // ── shot 4: the Admin on the same dashboard with "Edit" ──
  const adminPage = await signedInDashboard(ctx, ADMIN, ADMIN_PW, ADMIN_TOTP);
  page = adminPage;
  assert(adminPage.url().startsWith(DASHBOARD), `the Admin landed on the same dashboard (${adminPage.url().split(/[?#]/)[0]})`);
  // NEEDS-LIVE-VERIFICATION: the exact presence selector for the Admin's "Edit"
  // control on Grafana 12.2 (same candidates as above, positive).
  assert((await adminPage.locator('[aria-label="Edit dashboard"]').count()
    + await adminPage.getByRole('button', { name: /^Edit$/ }).count()) > 0, 'the Admin sees an "Edit" control on the dashboard');
  await shot(adminPage, 'admin-dashboard', `Admin ${ADMIN} on the same dashboard with "Edit" (the realm group decides the role)`);

  // ── shot 5: after logout, the Keycloak password form (no confirmation page) ──
  await adminPage.goto(`${G}/logout`, { waitUntil: 'networkidle' });
  await adminPage.waitForTimeout(2000);
  // lab6 (logs/170): /grafana/logout ends at the Keycloak form via end_session; U9: no
  // confirmation page.
  assert(/do you want to log out/i.test(await adminPage.textContent('body')) === false, 'logout shows no confirmation page');
  if (!(await adminPage.locator('#kc-form-login').count())) {
    // The end-session redirect lands on /grafana/login; the next authorize must show the form.
    await adminPage.goto(`${G}/login/generic_oauth`, { waitUntil: 'networkidle' });
  }
  await adminPage.waitForSelector('#kc-form-login', { timeout: 30000 });
  assert((await adminPage.locator('#kc-form-login').count()) === 1, 'after the Grafana logout the Keycloak password form is shown (the session is gone)');
  await shot(adminPage, 'after-logout', 'After the Grafana logout the user is signed out of the realm: the next sign-in asks for the password again');

  writeManifest();
  const total = manifest.reduce((k, m) => k + m.asserted.length, 0);
  // Mac vantage (F3): no external host may have been attempted (fingerprint at rest: M5 run 3).
  if (ext) ext.assertClean();
  if (manifest.length !== SHOTS_EXPECTED) throw new Error(`expected exactly ${SHOTS_EXPECTED} screenshots, wrote ${manifest.length}`);
  console.log(`STORY OK: ${total} assertions over ${manifest.length} screenshots`);
} catch (e) {
  // The failure capture bypasses the assertion-before-shot rule (it documents where
  // the story stopped); the expected-count check of the runner then fails the row.
  if (page) await capture(page, 'failure', `Story failed: ${String(e.message || e).slice(0, 160)}`).catch(() => {});
  writeManifest();
  console.error('STORY FAILED: ' + String(e.message || e).slice(0, 400));
  process.exitCode = 1;
} finally {
  // PRE-5: the browser evidence is read from the LIVE page; after browser.close() page.evaluate throws,
  // userAgent became '' and the HeadlessChrome refusal in browserEvidence could never fire.
  try {
    const ev = await browserEvidence({ browser, mode: launch.mode, rules: launch.rules, headless: launch.headless, page, cert: PIN, extra: { story: 'X3', certDecision, externalAttempts: ext ? ext.list : null, shotsExpected: SHOTS_EXPECTED } });
    writeFileSync(`${OUT}/browser.json`, JSON.stringify(ev, null, 2));
    chmodSync(`${OUT}/browser.json`, 0o644);
  } catch (e2) {
    console.error('browser.json not written: ' + String(e2.message || e2).slice(0, 160));
    if (MAC) process.exitCode = 1;
  }
  await browser.close();
  if (MAC) cleanProfile(launch.profileDir, process.exitCode === 1);
}
console.log('X3 vantage: ' + (MAC ? 'Mac: installed Chrome, fresh profile, pinned certificate, interstitial + Proceed, external attempts tracked' : 'container: walked harness image shape'));
