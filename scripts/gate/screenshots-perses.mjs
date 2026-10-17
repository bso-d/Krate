// End-user screenshot story for the identity gate, Phase 4b Perses (row X4).
// STATUS: LIVE-VERIFIED AND WIRED as runner-owned X4 in gate-identity.sh.
// The live 4b walk ran this story in container Chromium: see
// harness/phase4/live4b/results.md (X4) and logs/144 for 20 assertions,
// six screenshots and a verified manifest. NEEDS-LIVE-VERIFICATION comments
// below are historical markers for selectors verified by that walk.
//
// Runs inside the harness Playwright container (krate-harness/playwright:1.60.0),
// the same image and invocation shape as screenshots.mjs (X1, unchanged):
// `--resolve-to IP` maps the public host (`--host NAME`, default localhost) to the
// Docker host gateway inside Chromium (--host-resolver-rules), so
// https://NAME:PERSES_PORT reaches the published Perses gateway exactly as an end
// user's browser on the host does.
//
//   node screenshots-perses.mjs --host krate-gate.test --perses-base https://krate-gate.test:13443 \
//        --out /out/perses --viewer-user V --admin-user A --disabled-user D --nogroup-user N \
//        --resolve-to 192.168.65.254
// Credentials come from the environment only: GATE_VIEWER_PASSWORD, GATE_VIEWER_TOTP,
// GATE_ADMIN_PASSWORD, GATE_ADMIN_TOTP (base32, as keycloak_login_flow.py enrol writes
// them), GATE_DISABLED_PASSWORD (the disabled user is refused at the password step),
// GATE_NOGROUP_PASSWORD and GATE_NOGROUP_TOTP (the no-group user passes Keycloak and
// is refused at /oauth2/callback). Nothing secret is printed or written.
//
// Story (X4: exactly 6 PNGs, own directory, own manifest.tsv with sha256; every
// shot is taken only after its DOM assertions passed — shot() refuses a capture
// with no preceding assertion):
//   1 the Keycloak password form reached from the Perses URL
//   2 the Viewer in a project without create/edit controls
//   3 the Admin in the same project, with its Add Dashboard, rename/delete and edit controls
//     ("Create Project" exists on the home page only: both roles are asserted there, not in a shot)
//   4 after logout, the Keycloak password form
//   5 the disabled user: Keycloak's "Account is disabled"
//   6 the no-group user: the refusal page at /oauth2/callback
//   7 (Mac vantage only) the certificate interstitial before step 1
//
// Browser vantage (scripts/gate/browser-launch.mjs): with GATE_BROWSER_MAC unset this is the
// walked container story (live4b ran it); with GATE_BROWSER_MAC=1 it drives the installed,
// signed, headed Google Chrome on the Mac — fresh profile, the fixture certificate pinned
// through Node with the name check on (the identity port and the Perses gateway port are both
// pinned), Chrome's own certificate interstitial with Advanced + Proceed on the Perses origin
// (one decision covers the host: M0 point 3), every shot's main document bound to the VM
// address and the served certificate, `MAP * ~NOTFOUND` keeping the browser offline, external
// attempts collected and failing the story. 6 PNGs in the container vantage, 7 with the
// interstitial shot in the Mac vantage.
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
const PBASE = (args['perses-base'] || `https://${HOST}:3443`).replace(/\/$/, '');
const OUT = args.out || '/out';
const VIEWER = args['viewer-user'];
const ADMIN = args['admin-user'];
const DISABLED = args['disabled-user'];
const NOGROUP = args['nogroup-user'];
const VIEWER_PW = process.env.GATE_VIEWER_PASSWORD;
const VIEWER_TOTP = process.env.GATE_VIEWER_TOTP;
const ADMIN_PW = process.env.GATE_ADMIN_PASSWORD;
const ADMIN_TOTP = process.env.GATE_ADMIN_TOTP;
const DISABLED_PW = process.env.GATE_DISABLED_PASSWORD;
const NOGROUP_PW = process.env.GATE_NOGROUP_PASSWORD;
const NOGROUP_TOTP = process.env.GATE_NOGROUP_TOTP;
if (!VIEWER || !VIEWER_PW || !VIEWER_TOTP || !ADMIN || !ADMIN_PW || !ADMIN_TOTP
  || !DISABLED || !DISABLED_PW || !NOGROUP || !NOGROUP_PW || !NOGROUP_TOTP) {
  console.error('need --viewer-user, --admin-user, --disabled-user, --nogroup-user and GATE_VIEWER_PASSWORD/GATE_VIEWER_TOTP/GATE_ADMIN_PASSWORD/GATE_ADMIN_TOTP/GATE_DISABLED_PASSWORD/GATE_NOGROUP_PASSWORD/GATE_NOGROUP_TOTP');
  process.exit(2);
}
const SHOTS_EXPECTED_MAC = 7; // +1: the certificate interstitial the trust-nothing Mac profile must show
const SHOTS_EXPECTED_CONTAINER = 6;

const asserted = [];
function assert(cond, what) { if (!cond) throw new Error('assert: ' + what); asserted.push(what); }
// Keycloak renders an (empty) error container per field on every form; the message is the
// first one with text (the X1 story's selector, live-verified there).
const ERROR_TEXT = '[id^="input-error"], #kc-error-message, .kc-feedback-text';
function errorLocator(page) { return page.locator(ERROR_TEXT).filter({ hasText: /\S/ }).first(); }
async function waitForError(page) {
  await errorLocator(page).waitFor({ state: 'visible', timeout: 30000 });
  return (await errorLocator(page).innerText()).trim();
}

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
  if (MAC && serve) serve.record(PERS_IP, PIN, slug, asserted);
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
  // X4 rule: every story shot is taken AFTER its DOM assertions passed — a capture
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
// The launch is shared with X1/X3/U15-U7 through browser-launch.mjs.
import { launchGateBrowser, macMode, acceptGateCertificate, attachServeTracker, browserEvidence, cleanProfile, requireCertFile, pinGateCertificate, externalAttemptsTracker } from './browser-launch.mjs';
const MAC = macMode();
const SHOTS_EXPECTED = MAC ? SHOTS_EXPECTED_MAC : SHOTS_EXPECTED_CONTAINER;
const CERT = MAC ? requireCertFile() : null;
// Pin both surfaces the story drives: the public HTTPS port (M4's probe) and the Perses
// gateway port of this story's own entry URL. Both are the fixture's server.crt.
const PERS_IP = resolveTo;
const PIN = MAC ? await pinGateCertificate({ host: HOST, port: 443, certPem: CERT.pem, connectHost: resolveTo }) : null;
const PINPERS_PORT = (new URL(PBASE).port ? Number(new URL(PBASE).port) : 443);
const PINPERS = MAC ? await pinGateCertificate({ host: HOST, port: PINPERS_PORT, certPem: CERT.pem, connectHost: resolveTo }) : null;
const launch = await launchGateBrowser(chromium, { host: HOST, resolveTo, outDir: OUT });
const browser = launch.browser;
let certDecision = null;

// lab7 (082): the gateway sends an anonymous visitor to /oauth2/start and on to the
// realm's authorization endpoint; the password form of realm krate is the landing page.
async function openPersesAtKeycloak(page) {
  await page.goto(`${PBASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('#kc-form-login', { timeout: 30000 });
  assert(page.url().includes('/identity/realms/krate/protocol/openid-connect/auth'),
    `the Perses URL reached the Keycloak authorization endpoint of realm krate (${page.url().split(/[?#]/)[0]})`);
  assert((await page.locator('#username').count()) === 1 && (await page.locator('#password').count()) === 1,
    'the Keycloak password form is shown');
}

// lab7 (082): after the gateway sign-in Perses lands on /sign-in offering its native
// provider button ("Sign in with Krate sign-in"); clicking it runs the Perses OIDC
// login (silent, on the existing Keycloak SSO session) and lands on the Perses home.
async function persesSignIn(page) {
  await page.waitForLoadState('networkidle');
  const provider = page.getByRole('button', { name: /Sign in with/i });
  if (page.url().includes('/sign-in') && (await provider.count())) {
    await provider.first().click();
    await page.waitForURL((u) => !u.toString().includes('/sign-in'), { timeout: 30000 });
    await page.waitForLoadState('networkidle');
  }
  assert(!page.url().includes('/sign-in') && !page.url().includes('/identity/'),
    `signed in to Perses (${page.url().split(/[?#]/)[0]})`);
}

async function keycloakLogin(page, user, password, totpB32) {
  await page.waitForSelector('#username', { timeout: 30000 });
  await page.fill('#username', user);
  await page.fill('#password', password);
  await page.click('#kc-login');
  await page.waitForSelector('#otp', { timeout: 30000 });
  await page.fill('#otp', totp(totpB32));
  await page.click('#kc-login');
}

let page = null;
// Mac vantage trackers: serve (per-shot main-document evidence) and ext (F3 external attempts).
const serve = MAC ? attachServeTracker(null) : null;
const ext = MAC ? externalAttemptsTracker(HOST) : null;
try {
  const ctx = MAC ? browser : await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
  page = MAC ? (ctx.pages()[0] || await ctx.newPage()) : await ctx.newPage();
  if (ext) { page.on('requestfailed', (r) => ext.onFailed(r)); serve.attach(page); }

  // ── Mac vantage gate: the trust-nothing profile must show and pass Chrome's own certificate
  // interstitial on the story's entry URL (the Perses gateway) before story step 1 (M0 points
  // 2-3; M5 run 2 for the render-after-reject order); one Advanced+Proceed covers this host,
  // both ports, for the whole story. The code proves only that the chain has no trusted root
  // (F2); the pins above carry name/date validity.
  if (MAC) {
    const decision = await acceptGateCertificate(page, `${PBASE}/`, {
      onAssert: (d) => {
        assert(d.seen, 'the trust-nothing profile saw Chrome\'s real certificate interstitial (none seen: a pre-trusted or reused profile)');
        assert(/ERR_CERT_AUTHORITY_INVALID/.test(d.error), `the interstitial carries net::ERR_CERT_AUTHORITY_INVALID (got: ${d.error || 'none'}; F2: the code ranks above name/date, so another code means another defect)`);
        assert(PIN && PINPERS && PIN.authorized && PINPERS.authorized, 'both the HTTPS and the Perses gateway ports are TLS-authorised against the pinned certificate with the name check on (Node pin, M4)');
      },
      onShot: async () => { await shot(page, 'certificate-warning', 'Chrome shows its own certificate warning for the untrusted fixture certificate on the Perses gateway origin; name and date validity are evidenced by the Node pins and the securityDetails assertions, not by this code'); },
    });
    assert(decision.decision === 'proceed', 'the story proceeded through Advanced -> Proceed (one decision covers this host; got: ' + (decision.decision || 'none') + ')');
    certDecision = decision;
  }

  // ── shot 1: the Keycloak password form reached from the Perses URL ──
  await openPersesAtKeycloak(page);
  await shot(page, 'keycloak-password-form', 'Opening the Perses URL sends the user to the Krate realm\'s password form (the gateway allows nobody in without the realm)');

  // ── shot 2: the Viewer in a project without create/edit controls ──
  await keycloakLogin(page, VIEWER, VIEWER_PW, VIEWER_TOTP);
  await persesSignIn(page);
  // Live-verified 2026-10-16 on the Rocky fixture (harness/x4-diag/): /projects lands on the home
  // page, whose project card link opens /projects/krate in the page. networkidle returns at once on
  // that client-side navigation, so a capture right after the click is the empty Perses shell (the
  // attempt-4 X4 shot, byte-identical); the heading "Krate", the tabs and the four "Krate — …"
  // dashboard links render within 3 s. Wait for that content, assert it, then the absences
  // (live: 0 matches each for the Viewer; the hidden "Add Dashboard"/"Rename project" items are not
  // in the accessibility tree). "Create Project" exists on the home page only (Perses
  // HomeViewHeroSection; the project page shows it to nobody, Admin included), so its absence is
  // asserted on the home page, paired with the Admin's presence on the same page below.
  await page.goto(`${PBASE}/projects`, { waitUntil: 'networkidle' });
  const projectLink = page.getByRole('link', { name: /krate/i }).first();
  assert((await projectLink.count()) === 1, "the Viewer's home page lists the krate project");
  assert((await page.getByRole('button', { name: /(add|create) project/i }).count()) === 0,
    'the Viewer\'s home page (/projects) offers no "Create Project" control');
  await projectLink.click();
  await page.waitForURL((u) => u.pathname === '/projects/krate', { timeout: 30000 });
  await page.getByRole('heading', { name: 'Krate', exact: true }).waitFor({ state: 'visible', timeout: 30000 });
  const dashboardLinks = page.getByRole('link', { name: /^Krate — / });
  await dashboardLinks.first().waitFor({ state: 'visible', timeout: 30000 });
  const tabs = (await page.getByRole('tab').allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').trim());
  assert(tabs.some((t) => t.startsWith('Dashboards')), `the krate project page shows its Dashboards tab (${tabs.join(', ')})`);
  const dashboards = await dashboardLinks.count();
  assert(dashboards >= 1, `the Viewer sees the project's dashboards (${dashboards} listed)`);
  assert((await page.getByRole('button', { name: /add dashboard/i }).count()) === 0, 'the Viewer sees no "Add Dashboard" control');
  assert((await page.getByRole('button', { name: /(rename|delete) project/i }).count()) === 0, 'the Viewer sees no "Rename/Delete project" control');
  assert((await page.locator('[aria-label="Edit"], button:has(svg[data-testid="EditIcon"])').count()) === 0, 'the Viewer sees no edit control in the project');
  await shot(page, 'viewer-project', `Viewer ${VIEWER} in the krate project: its dashboards, no create, edit, rename or delete controls`);
  await ctx.clearCookies();
  await page.close();

  // ── shot 3: the Admin in the same project, with the create/edit controls the Viewer does not have ──
  page = await ctx.newPage();
  if (ext) { page.on('requestfailed', (r) => ext.onFailed(r)); serve.attach(page); }
  await openPersesAtKeycloak(page);
  await keycloakLogin(page, ADMIN, ADMIN_PW, ADMIN_TOTP);
  await persesSignIn(page);
  // The same selectors as the Viewer's absences in shot 2 must match for the Admin, or those
  // absences prove nothing. Observed live on the kept fixture: the Admin's project page shows
  // "Add Dashboard", the rename and delete project buttons and four edit icons, its home page
  // "Create Project"; the Viewer sees none of them. The "Admin" header link is shown to every
  // signed-in user, so it is no control. "Create Project" is asserted on the home page first
  // (the Viewer's absence is asserted on that same page); the shot is then taken in the project,
  // like shot 2, so that the controls on screen are the ones the manifest lists for it.
  await page.goto(`${PBASE}/projects`, { waitUntil: 'networkidle' });
  const addProject = page.getByRole('button', { name: /(add|create) project/i });
  await addProject.first().waitFor({ state: 'visible', timeout: 30000 });
  assert((await addProject.count()) > 0,
    'the Admin\'s home page (/projects) offers the "Create Project" control the Viewer\'s does not (asserted before the capture; the capture is the project page)');
  await page.goto(`${PBASE}/projects/krate`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'Krate', exact: true }).waitFor({ state: 'visible', timeout: 30000 });
  const adminAddDashboard = page.getByRole('button', { name: /add dashboard/i });
  await adminAddDashboard.first().waitFor({ state: 'visible', timeout: 30000 });
  assert((await adminAddDashboard.count()) > 0, 'the Admin sees the "Add Dashboard" control the Viewer does not');
  assert((await page.getByRole('button', { name: /(rename|delete) project/i }).count()) > 0,
    'the Admin sees the "Rename/Delete project" controls the Viewer does not');
  // The edit icons are per-row actions of the dashboard list, which renders after the lists load,
  // whereas "Add Dashboard" renders at once: wait for the rows (as the Viewer's wait does) before counting them.
  await page.getByRole('link', { name: /^Krate — / }).first().waitFor({ state: 'visible', timeout: 30000 });
  assert((await page.locator('[aria-label="Edit"], button:has(svg[data-testid="EditIcon"])').count()) > 0,
    'the Admin sees edit controls in the project, which the Viewer does not');
  await shot(page, 'admin-project', `Admin ${ADMIN} in the krate project: Add Dashboard, rename and delete project, edit icons (Create Project is on the home page, asserted before this capture)`);

  // ── shot 4: after logout, the Keycloak password form ──
  // lab7 (082): the account menu holds a plain anchor <A href="/api/auth/logout">;
  // clicking it runs the hop chain to the Keycloak login form with no confirmation page.
  // NEEDS-LIVE-VERIFICATION: the account-menu trigger selector (lab7 logged its
  // presence, not its selector).
  // The live walks ran this step from the home page: return there (shot 3 is taken in the project).
  await page.goto(`${PBASE}/projects`, { waitUntil: 'networkidle' });
  const accountMenu = page.locator('header button:has(svg), header [aria-haspopup="menu"], header .MuiAvatar-root, header [data-testid="AccountCircleIcon"]').last();
  await accountMenu.click();
  const logout = page.locator('a[href="/api/auth/logout"]');
  await logout.waitFor({ state: 'visible', timeout: 15000 });
  assert((await logout.count()) === 1, 'the account menu holds the Logout anchor to /api/auth/logout');
  await logout.click();
  await page.waitForSelector('#kc-form-login', { timeout: 30000 });
  assert(/do you want to log out/i.test(await page.textContent('body')) === false, 'logout shows no confirmation page');
  assert((await page.locator('#kc-form-login').count()) === 1, 'after the Perses logout the Keycloak password form is shown (gateway, Perses and realm sessions are gone)');
  await shot(page, 'after-logout', 'One logout from the Perses account menu ends every session: the next visit asks for the password again');
  await ctx.clearCookies();
  await page.close();

  // ── shot 5: the disabled user is refused by Keycloak ──
  page = await ctx.newPage();
  if (ext) { page.on('requestfailed', (r) => ext.onFailed(r)); serve.attach(page); }
  await openPersesAtKeycloak(page);
  await page.fill('#username', DISABLED);
  await page.fill('#password', DISABLED_PW);
  await page.click('#kc-login');
  const disMsg = await waitForError(page);
  assert(/account is disabled/i.test(disMsg), `the disabled user is refused by the realm with: ${disMsg}`);
  await shot(page, 'disabled-user-refused', `Disabled user ${DISABLED}: the realm refuses the sign-in ("Account is disabled"), so Perses never sees the user`);
  await ctx.clearCookies();
  await page.close();

  // ── shot 6: the no-group user is refused at /oauth2/callback ──
  page = await ctx.newPage();
  if (ext) { page.on('requestfailed', (r) => ext.onFailed(r)); serve.attach(page); }
  await openPersesAtKeycloak(page);
  await keycloakLogin(page, NOGROUP, NOGROUP_PW, NOGROUP_TOTP);
  await page.waitForLoadState('networkidle');
  // V4: refused at /oauth2/callback with no Perses cookie set.
  // NEEDS-LIVE-VERIFICATION: the refusal page's exact content (oauth2-proxy's 403
  // answer at the callback); lab2 proved the refusal and the absent cookie by HTTP.
  assert(page.url().includes('/oauth2/callback') || /forbidden|403|access denied/i.test(await page.textContent('body')),
    `the no-group user is refused at the gateway callback (${page.url().split(/[?#]/)[0]})`);
  const cookies = (await ctx.cookies()).map((c) => c.name);
  assert(!cookies.includes('jwtPayload') && !cookies.includes('jwtRefreshToken'),
    `no Perses session cookie was set (cookies: ${cookies.join(', ') || 'none'})`);
  await shot(page, 'nogroup-user-refused', `User ${NOGROUP} without a realm group: the gateway refuses the callback and Perses issues no session`);

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
    const ev = await browserEvidence({ browser, mode: launch.mode, rules: launch.rules, headless: launch.headless, page, cert: PIN, extra: { story: 'X4', certDecision, externalAttempts: ext ? ext.list : null, shotsExpected: SHOTS_EXPECTED, persesPortPin: PINPERS ? { port: PINPERS_PORT, authorized: PINPERS.authorized, protocol: PINPERS.protocol, sha256: PINPERS.sha256 } : null } });
    writeFileSync(`${OUT}/browser.json`, JSON.stringify(ev, null, 2));
    chmodSync(`${OUT}/browser.json`, 0o644);
  } catch (e2) {
    console.error('browser.json not written: ' + String(e2.message || e2).slice(0, 160));
    if (MAC) process.exitCode = 1;
  }
  await browser.close();
  if (MAC) cleanProfile(launch.profileDir, process.exitCode === 1);
}
console.log('X4 vantage: ' + (MAC ? 'Mac: installed Chrome, fresh profile, pinned certificate (HTTPS + Perses ports), interstitial + Proceed, external attempts tracked' : 'container: walked harness image shape'));
