// End-user screenshot story for the identity gate (Phase 1). Runs inside the harness
// Playwright container; `--resolve-to IP` maps the name `localhost` to the Docker host
// gateway inside Chromium (--host-resolver-rules), so https://localhost[:port] reaches
// the published proxy port exactly as an end user's browser on the host does.
//
//   node screenshots.mjs --base https://localhost:8443 --out /out --user U --disabled-user D --resolve-to 192.168.65.254
// Passwords come from the environment: GATE_TEMP_PASSWORD (U's temporary password),
// GATE_DISABLED_PASSWORD (D's). Nothing secret is printed or written: the TOTP QR code
// and secret are masked before that page is captured, and each step asserts its outcome
// (the OTP prompt, the refusal messages, the 404s) and records it in manifest.json.
//
// Story (one PNG per step, numbered): account console asks to sign in -> login form ->
// TOTP enrolment -> forced password change -> signed-in account console -> sign out ->
// second login asks for the OTP -> wrong password refused -> disabled user refused ->
// admin console and master realm are not reachable through the proxy.
//
// Browser vantage (scripts/gate/browser-launch.mjs): with GATE_BROWSER_MAC unset this is the
// walked container story (X1, live receipts use it); with GATE_BROWSER_MAC=1 it drives the
// installed, signed, headed Google Chrome on the Mac (fresh profile, the fixture certificate
// pinned through Node, Chrome's own interstitial with Advanced + Proceed, the served
// certificate and server address asserted, `MAP * ~NOTFOUND` keeping the browser offline).
// X1 stays a Mac-fixture row: the runner refuses the agent vantage for Phase 1-3
// (TOPOFIX-REVIEW F9) because mapping the name `localhost` onto a non-loopback address is not
// what a user does. 11 PNGs in the container vantage, 12 with the one certificate-interstitial
// shot in the Mac vantage.
import { createRequire } from 'node:module';
// The harness image installs playwright globally; ESM ignores NODE_PATH, so resolve it explicitly.
const require = createRequire(process.env.PW_MODULES ? process.env.PW_MODULES + '/resolve-from-here.js' : import.meta.url);
const { chromium } = require('playwright');
import { createHmac, randomInt } from 'node:crypto';
import { writeFileSync, chmodSync } from 'node:fs';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, v, i, arr) => {
  if (v.startsWith('--')) acc.push([v.slice(2), arr[i + 1]]);
  return acc;
}, []));
const BASE = (args.base || 'https://localhost').replace(/\/$/, '');
const OUT = args.out || '/out';
const USER = args.user;
const DISABLED = args['disabled-user'];
const TEMP_PW = process.env.GATE_TEMP_PASSWORD;
const DISABLED_PW = process.env.GATE_DISABLED_PASSWORD;
if (!USER || !TEMP_PW || !DISABLED || !DISABLED_PW) { console.error('need --user, --disabled-user, GATE_TEMP_PASSWORD and GATE_DISABLED_PASSWORD'); process.exit(2); }
const asserted = [];
function assert(cond, what) { if (!cond) throw new Error('assert: ' + what); asserted.push(what); }
// Keycloak renders an (empty) error container per field on every form; the message is the first one with text.
const ERROR_TEXT = '[id^="input-error"], #kc-error-message, .kc-feedback-text';
function errorLocator() { return page.locator(ERROR_TEXT).filter({ hasText: /\S/ }).first(); }
async function waitForError() { await errorLocator().waitFor({ state: 'visible', timeout: 30000 }); return (await errorLocator().innerText()).trim(); }
const NEW_PW = [...Array(18)].map(() => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789'[randomInt(54)]).join('');
let certDecision = null;

function totp(secretBytes, t = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(t / 30)));
  const d = createHmac('sha1', secretBytes).update(counter).digest();
  const o = d[d.length - 1] & 15;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// Manifests and step records are published evidence: keep only origin+path,
// never the query or fragment (authorization codes, state and nonce are
// transient credentials, not evidence).
function publicUrl(u) { try { const x = new URL(u); return x.origin + x.pathname; } catch { return String(u).split(/[?#]/)[0]; } }
let n = 0;
const manifest = [];
async function shot(page, slug, caption) {
  n += 1;
  // Mac vantage: bind the shot's main document to the VM address and the pinned certificate
  // (assertServedFrom/assertServedCertificate; M0 point 4 observed the fields).
  if (MAC && serve) serve.record(resolveTo, PIN, slug, asserted);
  const file = `${String(n).padStart(2, '0')}-${slug}.png`;
  await page.screenshot({ path: `${OUT}/${file}`, fullPage: false });
  manifest.push({ file, caption, url: publicUrl(page.url()), asserted: asserted.splice(0) });
  console.log(`${file}\t${caption}`);
}

const resolveTo = args['resolve-to'];
// The launch is shared with X3/X4/U15-U7 through browser-launch.mjs: container vantage keeps
// the walked launch bytes, the Mac vantage (GATE_BROWSER_MAC=1) requires the pinned fixture
// certificate and drives the installed Chrome.
import { launchGateBrowser, macMode, acceptGateCertificate, attachServeTracker, browserEvidence, cleanProfile, requireCertFile, pinGateCertificate, externalAttemptsTracker } from './browser-launch.mjs';
const MAC = macMode();
const PORT_FOR_PIN = (new URL(BASE).port ? Number(new URL(BASE).port) : 443);
const CERT = MAC ? requireCertFile() : null;
const PIN = MAC ? await pinGateCertificate({ host: 'localhost', port: PORT_FOR_PIN, certPem: CERT.pem, connectHost: resolveTo }) : null;
const launch = await launchGateBrowser(chromium, { host: 'localhost', resolveTo, outDir: OUT, viewport: MAC ? { width: 1440, height: 900 } : { width: 1280, height: 800 } });
const browser = launch.browser;
// In the Mac vantage `browser` IS the persistent context with its first page; in the
// container vantage this is the walked newContext shape.
const ctx = MAC ? browser : await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
const page = MAC ? (ctx.pages()[0] || await ctx.newPage()) : await ctx.newPage();
const serve = MAC ? attachServeTracker(page) : null;
// Mac vantage (F3): every failed request whose host is not the gate host is an external
// attempt; the row fails on any that is not Chrome-internal (chrome://, devtools://).
const ext = MAC ? externalAttemptsTracker('localhost') : null;
if (ext) page.on('requestfailed', (r) => ext.onFailed(r));
const account = `${BASE}/identity/realms/krate/account`;

async function openLogin() {
  await page.goto(account, { waitUntil: 'networkidle' });
  const signIn = page.getByRole('button', { name: /sign in/i });
  if (!(await page.locator('#kc-form-login').count()) && (await signIn.count())) await signIn.first().click();
  await page.waitForSelector('#kc-form-login');
}

try {
  // Mac vantage gate: the trust-nothing profile must see and pass Chrome's own certificate
  // interstitial first (M0 points 2-3; M5 run 2 for the render-after-reject order); one
  // Advanced+Proceed decision covers this host for the whole story. The code proves only that
  // the chain has no trusted root (F2); name and date validity are the Node pin + Mac-clock
  // check done above in pinGateCertificate.
  if (MAC) {
    const decision = await acceptGateCertificate(page, account, {
      onAssert: (d) => {
        assert(d.seen, 'the trust-nothing profile saw Chrome\'s real certificate interstitial (none seen: a pre-trusted or reused profile)');
        assert(/ERR_CERT_AUTHORITY_INVALID/.test(d.error), `the interstitial carries net::ERR_CERT_AUTHORITY_INVALID (got: ${d.error || 'none'}; F2: the code ranks above name/date, so another code means another defect)`);
      },
      onShot: async () => { await shot(page, 'certificate-warning', 'Chrome shows its own certificate warning for the untrusted fixture certificate (decision per exact certificate in this fresh profile); name and date validity are evidenced by the Node pin and the securityDetails assertions, not by this code'); },
    });
    assert(decision.decision === 'proceed', 'the story proceeded through Advanced -> Proceed (one decision covers this host; got: ' + (decision.decision || 'none') + ')');
    certDecision = decision;
  }
  // Verified in Chrome DevTools (2026-10-10): the unauthenticated account console redirects
  // straight to the realm login form (#kc-form-login, #username, #password, #kc-login).
  await openLogin();
  await shot(page, 'login-form', 'Opening the account console sends the user to the Krate login form (username + password) through the HTTPS proxy');

  await page.fill('#username', USER);
  await page.fill('#password', TEMP_PW);
  await page.click('#kc-login');
  let totpSecret = null;
  for (let i = 0; i < 3; i += 1) {
    if (await page.locator('input[name="totpSecret"]').count()) {
      const raw = await page.locator('input[name="totpSecret"]').inputValue();
      totpSecret = Buffer.from(raw, 'latin1');
      // The QR code and the typed secret encode the enrolment seed: masked before the capture,
      // so the published PNG carries no credential (the gate's leak scan covers the captions only).
      await page.addStyleTag({ content: '#kc-totp-secret-qr-code, #kc-totp-secret-key, .kc-totp-secret-qr-code, [id*="totp-secret"] img { visibility: hidden !important; }' });
      await page.evaluate(() => { for (const el of document.querySelectorAll('img[src^="data:image"]')) el.style.visibility = 'hidden'; for (const el of document.querySelectorAll('#kc-totp-secret-key, span[id*="secret"]')) el.textContent = '(masked by the gate)'; });
      await shot(page, 'totp-enrolment-required', 'First login: the user must enrol an authenticator app (TOTP) before continuing (QR code and secret masked)');
      await page.fill('#totp', totp(totpSecret));
      await page.locator('input[name="userLabel"]').fill('phone');
      await page.locator('#saveTOTPBtn, input[type="submit"], button[type="submit"]').first().click();
      await page.waitForLoadState('networkidle');
      continue;
    }
    if (await page.locator('#password-new').count()) {
      await shot(page, 'password-change-required', 'First login: the temporary password must be replaced');
      await page.fill('#password-new', NEW_PW);
      await page.fill('#password-confirm', NEW_PW);
      await page.locator('#kc-form-buttons input[type="submit"], button[type="submit"]').first().click();
      await page.waitForLoadState('networkidle');
      continue;
    }
    break;
  }
  await page.waitForURL((u) => u.toString().startsWith(account), { timeout: 30000 });
  await page.waitForLoadState('networkidle');
  await shot(page, 'signed-in-account-console', `Signed in as ${USER}: the account console shows the user's own profile only`);

  // Sign out through the console menu; fall back to the end-session endpoint.
  const signOut = page.getByRole('button', { name: /sign out/i }).or(page.getByRole('menuitem', { name: /sign out/i }));
  if (await signOut.count()) { await signOut.first().click(); await page.waitForLoadState('networkidle'); }
  await ctx.clearCookies();

  await openLogin();
  await page.fill('#username', USER);
  await page.fill('#password', NEW_PW);
  await page.click('#kc-login');
  await page.waitForSelector('#otp');
  assert(!(await page.locator('#password').count()), 'the second login asks for the OTP (no password field on this page)');
  await shot(page, 'second-login-asks-otp', 'Every later login asks for the one-time code after the password');
  await page.fill('#otp', '000000');
  await page.click('#kc-login');
  const otpMsg = await waitForError();
  assert(/invalid authenticator code/i.test(otpMsg) && (await page.locator('#otp').count()), `wrong OTP refused on the OTP form with: ${otpMsg}`);
  await shot(page, 'wrong-otp-refused', 'A wrong one-time code is refused');
  await ctx.clearCookies();

  await openLogin();
  await page.fill('#username', USER);
  await page.fill('#password', 'definitely-not-the-password');
  await page.click('#kc-login');
  const pwMsg = await waitForError();
  assert(/invalid username or password/i.test(pwMsg) && (await page.locator('#kc-form-login').count()), `wrong password refused on the login form with: ${pwMsg}`);
  await shot(page, 'wrong-password-refused', 'A wrong password is refused with a generic message');
  await ctx.clearCookies();

  await openLogin();
  await page.fill('#username', DISABLED);
  await page.fill('#password', DISABLED_PW);
  await page.click('#kc-login');
  const disMsg = await waitForError();
  assert(/account is disabled/i.test(disMsg), `disabled user refused with: ${disMsg}`);
  await shot(page, 'disabled-user-refused', `Disabled user ${DISABLED}: the login is refused`);
  await ctx.clearCookies();

  for (const [path, slug, caption] of [
    ['/identity/admin/', 'admin-console-blocked', 'The Keycloak admin console is not reachable through the public proxy (404)'],
    ['/identity/realms/master/account', 'master-realm-blocked', 'The master realm is not reachable through the public proxy (404)'],
    ['/identity/metrics', 'metrics-blocked', 'Metrics are not reachable through the public proxy (404)'],
  ]) {
    const resp = await page.goto(`${BASE}${path}`, { waitUntil: 'load' });
    assert(resp && resp.status() === 404, `${path} answers HTTP ${resp ? resp.status() : '?'} (404 required)`);
    await shot(page, slug, `${caption}; HTTP ${resp.status()}`);
  }
  // Mac vantage (F3): no external host may have been attempted; the fingerprint a violation
  // would show is net::ERR_NAME_NOT_RESOLVED (M5 run 3).
  if (ext) ext.assertClean();
  // S2 (review): X1 asserts its own exact count in both vantages, the way X3/X4 do — 11 in the
  // walked container vantage, 12 with the one certificate-interstitial shot in the Mac vantage.
  const SHOTS_EXPECTED = MAC ? 12 : 11;
  if (manifest.length !== SHOTS_EXPECTED) throw new Error(`expected exactly ${SHOTS_EXPECTED} screenshots, wrote ${manifest.length}`);
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2));
  chmodSync(`${OUT}/manifest.json`, 0o644);
  console.log(`STORY OK: ${manifest.reduce((k, m) => k + m.asserted.length, 0)} assertions over ${manifest.length} screenshots`);
} catch (e) {
  await shot(page, 'failure', `Story failed: ${String(e.message || e).slice(0, 160)}`);
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.error('STORY FAILED: ' + String(e.message || e).slice(0, 400));
  process.exitCode = 1;
} finally {
  await browser.close();
  try {
    const ev = await browserEvidence({ browser, mode: launch.mode, rules: launch.rules, headless: launch.headless, page, cert: PIN, extra: { story: 'X1', certDecision, externalAttempts: ext ? ext.list : null } });
    writeFileSync(`${OUT}/browser.json`, JSON.stringify(ev, null, 2));
    chmodSync(`${OUT}/browser.json`, 0o644);
  } catch (e) {
    console.error('browser.json not written: ' + String(e.message || e).slice(0, 160));
    if (MAC) process.exitCode = 1;
  }
  if (MAC) cleanProfile(launch.profileDir, process.exitCode === 1);
}
console.log('X1 vantage: ' + (MAC ? 'Mac: installed Chrome, fresh profile, pinned certificate, interstitial + Proceed, external attempts tracked' : 'container: walked harness image shape'));
