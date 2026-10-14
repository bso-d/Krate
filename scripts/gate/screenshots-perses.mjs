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
//   3 the Admin with "Add Project"/edit controls
//   4 after logout, the Keycloak password form
//   5 the disabled user: Keycloak's "Account is disabled"
//   6 the no-group user: the refusal page at /oauth2/callback
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
const SHOTS_EXPECTED = 6;

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

let n = 0;
const manifest = [];
async function capture(page, slug, caption) {
  n += 1;
  const file = `${String(n).padStart(2, '0')}-${slug}.png`;
  await page.screenshot({ path: `${OUT}/${file}`, fullPage: false });
  const bytes = readFileSync(`${OUT}/${file}`);
  manifest.push({
    file, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length,
    caption, url: page.url(), asserted: asserted.splice(0),
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
    ...manifest.map((m) => [m.file, m.sha256, m.bytes, m.caption, m.url, m.asserted.join(' | ')].join('\t'))].join('\n');
  writeFileSync(`${OUT}/manifest.tsv`, tsv + '\n');
  chmodSync(`${OUT}/manifest.tsv`, 0o644);
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2)); // convenience copy; the runner asserts on manifest.tsv
  chmodSync(`${OUT}/manifest.json`, 0o644);
}

mkdirSync(OUT, { recursive: true });
const resolveTo = args['resolve-to'];
const launchArgs = resolveTo ? [`--host-resolver-rules=MAP ${HOST} ${resolveTo}`] : [];
const browser = await chromium.launch({ args: launchArgs });

// lab7 (082): the gateway sends an anonymous visitor to /oauth2/start and on to the
// realm's authorization endpoint; the password form of realm krate is the landing page.
async function openPersesAtKeycloak(page) {
  await page.goto(`${PBASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('#kc-form-login', { timeout: 30000 });
  assert(page.url().includes('/identity/realms/krate/protocol/openid-connect/auth'),
    `the Perses URL reached the Keycloak authorization endpoint of realm krate (${page.url().split('?')[0]})`);
  assert((await page.locator('#username').count()) === 1 && (await page.locator('#password').count()) === 1,
    'the Keycloak password form is shown');
}

// lab7 (082): after the gateway sign-in Perses lands on /sign-in offering its native
// provider button ("Sign in with Company sign-in"); clicking it runs the Perses OIDC
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
    `signed in to Perses (${page.url()})`);
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
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', timezoneId: 'UTC', viewport: { width: 1440, height: 900 } });
  page = await ctx.newPage();

  // ── shot 1: the Keycloak password form reached from the Perses URL ──
  await openPersesAtKeycloak(page);
  await shot(page, 'keycloak-password-form', 'Opening the Perses URL sends the user to the Krate realm\'s password form (the gateway allows nobody in without the realm)');

  // ── shot 2: the Viewer in a project without create/edit controls ──
  await keycloakLogin(page, VIEWER, VIEWER_PW, VIEWER_TOTP);
  await persesSignIn(page);
  // NEEDS-LIVE-VERIFICATION: the navigation into the project (lab7's home page listed
  // the project card; the walk notes must confirm the click path and the URL).
  await page.goto(`${PBASE}/projects`, { waitUntil: 'networkidle' });
  const projectLink = page.getByRole('link', { name: /krate/i }).first();
  if (await projectLink.count()) await projectLink.click();
  await page.waitForLoadState('networkidle');
  assert(page.url().includes('/projects/'), `the Viewer reached a project page (${page.url()})`);
  // NEEDS-LIVE-VERIFICATION: the exact absence selectors for the Viewer (Perses
  // v0.54.0): no "Add Project"/create button, no dashboard edit (pencil) control.
  assert((await page.getByRole('button', { name: /(add|create) project/i }).count()) === 0, 'the Viewer sees no "Create Project" control');
  assert((await page.locator('[aria-label="Edit"], button:has(svg[data-testid="EditIcon"])').count()) === 0, 'the Viewer sees no edit control in the project');
  await shot(page, 'viewer-project', `Viewer ${VIEWER} in a project: read-only, no create/edit controls`);
  await ctx.clearCookies();
  await page.close();

  // ── shot 3: the Admin with "Add Project"/edit controls ──
  page = await ctx.newPage();
  await openPersesAtKeycloak(page);
  await keycloakLogin(page, ADMIN, ADMIN_PW, ADMIN_TOTP);
  await persesSignIn(page);
  // NEEDS-LIVE-VERIFICATION: the exact presence selector of the Admin's "Add Project"
  // button and of a dashboard edit control (lab7 recorded the Admin-side page text
  // "Admin Config"; the walk notes must confirm the buttons).
  await page.goto(`${PBASE}/projects`, { waitUntil: 'networkidle' });
  const addProject = page.getByRole('button', { name: /(add|create) project/i });
  const adminMenu = page.getByRole('link', { name: /^Admin$/i }).or(page.getByRole('button', { name: /^Admin$/i }));
  assert((await addProject.count()) > 0 || (await adminMenu.count()) > 0,
    'the Admin sees the "Create Project" control or the Admin section (an editor\'s UI)');
  await shot(page, 'admin-projects', `Admin ${ADMIN} with the create/edit controls of the realm's admin group`);

  // ── shot 4: after logout, the Keycloak password form ──
  // lab7 (082): the account menu holds a plain anchor <A href="/api/auth/logout">;
  // clicking it runs the hop chain to the Keycloak login form with no confirmation page.
  // NEEDS-LIVE-VERIFICATION: the account-menu trigger selector (lab7 logged its
  // presence, not its selector).
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
  await openPersesAtKeycloak(page);
  await keycloakLogin(page, NOGROUP, NOGROUP_PW, NOGROUP_TOTP);
  await page.waitForLoadState('networkidle');
  // V4: refused at /oauth2/callback with no Perses cookie set.
  // NEEDS-LIVE-VERIFICATION: the refusal page's exact content (oauth2-proxy's 403
  // answer at the callback); lab2 proved the refusal and the absent cookie by HTTP.
  assert(page.url().includes('/oauth2/callback') || /forbidden|403|access denied/i.test(await page.textContent('body')),
    `the no-group user is refused at the gateway callback (${page.url().split('?')[0]})`);
  const cookies = (await ctx.cookies()).map((c) => c.name);
  assert(!cookies.includes('jwtPayload') && !cookies.includes('jwtRefreshToken'),
    `no Perses session cookie was set (cookies: ${cookies.join(', ') || 'none'})`);
  await shot(page, 'nogroup-user-refused', `User ${NOGROUP} without a realm group: the gateway refuses the callback and Perses issues no session`);

  writeManifest();
  const total = manifest.reduce((k, m) => k + m.asserted.length, 0);
  if (manifest.length !== SHOTS_EXPECTED) throw new Error(`expected exactly ${SHOTS_EXPECTED} screenshots, wrote ${manifest.length}`);
  console.log(`STORY OK: ${total} assertions over ${manifest.length} screenshots`);
} catch (e) {
  // The failure capture bypasses the assertion-before-shot rule (it documents where
  // the story stopped); the exact-6-PNG count of the runner then fails the row.
  if (page) await capture(page, 'failure', `Story failed: ${String(e.message || e).slice(0, 160)}`).catch(() => {});
  writeManifest();
  console.error('STORY FAILED: ' + String(e.message || e).slice(0, 400));
  process.exitCode = 1;
} finally {
  await browser.close();
}
