// End-user screenshot story for the identity gate (Phase 1). Runs inside the harness
// Playwright container with the nginx proxy's network namespace, so https://localhost
// is the proxy exactly as an end user on the VM would see it.
//
//   node screenshots.mjs --base https://localhost --out /out --user U --disabled-user D
// Passwords come from the environment: GATE_TEMP_PASSWORD (U's temporary password),
// GATE_DISABLED_PASSWORD (D's). Nothing secret is printed or written.
//
// Story (one PNG per step, numbered): account console asks to sign in -> login form ->
// TOTP enrolment -> forced password change -> signed-in account console -> sign out ->
// second login asks for the OTP -> wrong password refused -> disabled user refused ->
// admin console and master realm are not reachable through the proxy.
import { chromium } from 'playwright';
import { createHmac } from 'node:crypto';
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
if (!USER || !TEMP_PW) { console.error('need --user and GATE_TEMP_PASSWORD'); process.exit(2); }
const NEW_PW = [...Array(18)].map(() => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789'[Math.floor(Math.random() * 54)]).join('');

function b32decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totp(secretBytes, t = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(t / 30)));
  const d = createHmac('sha1', secretBytes).update(counter).digest();
  const o = d[d.length - 1] & 15;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let n = 0;
const manifest = [];
async function shot(page, slug, caption) {
  n += 1;
  const file = `${String(n).padStart(2, '0')}-${slug}.png`;
  await page.screenshot({ path: `${OUT}/${file}`, fullPage: false });
  manifest.push({ file, caption, url: page.url() });
  console.log(`${file}\t${caption}`);
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
const page = await ctx.newPage();
const account = `${BASE}/identity/realms/krate/account`;

try {
  await page.goto(account, { waitUntil: 'networkidle' });
  await shot(page, 'account-console-asks-to-sign-in', 'Opening the account console: Keycloak asks the user to sign in');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForSelector('#kc-form-login');
  await shot(page, 'login-form', 'Krate realm login form (username + password), served through the HTTPS proxy');

  await page.fill('#username', USER);
  await page.fill('#password', TEMP_PW);
  await page.click('#kc-login');
  let totpSecret = null;
  for (let i = 0; i < 3; i += 1) {
    if (await page.locator('input[name="totpSecret"]').count()) {
      const raw = await page.locator('input[name="totpSecret"]').inputValue();
      totpSecret = Buffer.from(raw, 'latin1');
      await shot(page, 'totp-enrolment-required', 'First login: the user must enrol an authenticator app (TOTP) before continuing');
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

  await page.goto(account, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForSelector('#kc-form-login');
  await page.fill('#username', USER);
  await page.fill('#password', NEW_PW);
  await page.click('#kc-login');
  await page.waitForSelector('#otp');
  await shot(page, 'second-login-asks-otp', 'Every later login asks for the one-time code after the password');
  await page.fill('#otp', '000000');
  await page.click('#kc-login');
  await page.waitForSelector('#otp');
  await shot(page, 'wrong-otp-refused', 'A wrong one-time code is refused');
  await ctx.clearCookies();

  await page.goto(account, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForSelector('#kc-form-login');
  await page.fill('#username', USER);
  await page.fill('#password', 'definitely-not-the-password');
  await page.click('#kc-login');
  await page.waitForSelector('#kc-form-login');
  await shot(page, 'wrong-password-refused', 'A wrong password is refused with a generic message');
  await ctx.clearCookies();

  if (DISABLED && DISABLED_PW) {
    await page.goto(account, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForSelector('#kc-form-login');
    await page.fill('#username', DISABLED);
    await page.fill('#password', DISABLED_PW);
    await page.click('#kc-login');
    await page.waitForLoadState('networkidle');
    await shot(page, 'disabled-user-refused', `Disabled user ${DISABLED}: the login is refused`);
    await ctx.clearCookies();
  }

  for (const [path, slug, caption] of [
    ['/identity/admin/', 'admin-console-blocked', 'The Keycloak admin console is not reachable through the public proxy (404)'],
    ['/identity/realms/master/account', 'master-realm-blocked', 'The master realm is not reachable through the public proxy (404)'],
    ['/identity/metrics', 'metrics-blocked', 'Metrics are not reachable through the public proxy (404)'],
  ]) {
    const resp = await page.goto(`${BASE}${path}`, { waitUntil: 'load' });
    await shot(page, slug, `${caption}; HTTP ${resp ? resp.status() : '?'}`);
  }
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2));
  chmodSync(`${OUT}/manifest.json`, 0o644);
  console.log('STORY OK');
} catch (e) {
  await shot(page, 'failure', `Story failed: ${String(e.message || e).slice(0, 160)}`);
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.error('STORY FAILED: ' + String(e.message || e).slice(0, 400));
  process.exitCode = 1;
} finally {
  await browser.close();
}
