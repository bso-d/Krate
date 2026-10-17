// Shared browser launch for the identity-gate screenshot stories (X1, X3, X4, U15/U7).
//
// Two vantages, decided by the caller's environment (rule 11: each shape below is what a
// live walk observed, cited per branch):
// - GATE_BROWSER_MAC unset (default): the container vantage. `chromium.launch` + a context
//   with `ignoreHTTPSErrors: true` and the one-name `--host-resolver-rules` mapping, exactly
//   the stories' walked behaviour (live4a/live4b; unchanged here so the walked receipts stay
//   valid). The container sits inside the air-gapped guest, so an outside fetch by a page is
//   a visible failure there — TOPOFIX-REVIEW F3's weaker-assertion problem does not exist in
//   this vantage.
// - GATE_BROWSER_MAC=1: the Mac vantage. The installed, signed Google Chrome (channel
//   'chrome') headed, a fresh profile per story, `ignoreHTTPSErrors` deliberately NOT set
//   (Chrome's own verifier runs), the name mapped to the VM's address with every OTHER name
//   forced to fail (`MAP * ~NOTFOUND`) and the VM address excluded from that catch-all, the
//   certificate pinned out-of-band, the first navigation expected to show Chrome's real
//   interstitial (Advanced + Proceed, M0/M5), the main-document server address asserted and
//   failed attempts collected. Licence: hand-walks 2026-10-17 m0.txt (M0) and m5
//   (phase4-browser.m5.mjs, the adapter these shapes were walked with).
//
// The interstitial code does NOT prove the name or the date are valid (TOPOFIX-REVIEW F2,
// observed in M0: a wrong-name and an expired certificate show the same
// net::ERR_CERT_AUTHORITY_INVALID): name and date validity are evidenced by the Node pin
// (authorised TLS against the pinned CA with the name check on), the pinned certificate's
// validity window against the Mac clock, and the served-certificate fields from
// Response.securityDetails compared with the pinned certificate (M0 point 4). CDP
// Network.getCertificate is NOT used: M0 point 6 — it returned {"tableNames": []} after
// Proceed in Chrome 155, so it has no certificate digest to give.
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';

// X509Certificate.subject/.issuer are multi-line DNs; Response.securityDetails() names are
// single values (CN-shaped). Compare on a folded, case-insensitive substring.
function dnFold(s) { return String(s || '').replace(/\s+/g, ' ').toLowerCase(); }

// The Mac launch flag (the stories' only behaviour switch): container runner keeps today's
// behaviour when it is unset, whatever else the environment says.
export function macMode() { return process.env.GATE_BROWSER_MAC === '1'; }

function exit2(msg) { console.error(msg); process.exit(2); }

// TOPOFIX-REVIEW F3: the Mac Chrome carries the owner's whole network; the resolver-rule
// catch-all keeps it offline. Every requestfailed of a non-gate host goes into
// external_attempts; a formal row FAILs on any entry that is not Chrome-internal (chrome://,
// devtools://). M5 run 3 observed the fingerprint at rest: `requestfailed holds only
// same-origin net::ERR_ABORTED (SPA route churn), no ERR_NAME_NOT_RESOLVED and no external
// URL` — an attempt would appear as ERR_NAME_NOT_RESOLVED under MAP * ~NOTFOUND.
export function externalAttemptsTracker(host) {
  const list = [];
  return {
    list,
    attach(page) { page.on('requestfailed', (r) => this.onFailed(r)); return this; },
    onFailed(r) {
      let u = null;
      try { u = new URL(r.url()); } catch { u = null; }
      if (!u) return;
      // The guard compares host NAMES, not host:port (review S1): the stories build the tracker
      // with the bare host, and X4's Perses origin is https://<host>:3443 — its own SPA churn
      // (M5 run 3 recorded the sibling SPA's at-rest net::ERR_ABORTED churn) is same-origin on
      // any port and must not be recorded as an external attempt.
      if (u.hostname !== host) list.push({ host: u.hostname, scheme: u.protocol.replace(':', ''), error: r.failure()?.errorText || '' });
    },
    // chrome:// and devtools:// targets are Chrome's own; everything else that failed must
    // not have been attempted at all (the resolver rule makes them NAME failures, hence the
    // ERR_NAME_NOT_RESOLVED fingerprint TOPOFIX-M5 records).
    assertClean() {
      const external = list.filter((e) => e.scheme !== 'chrome' && e.scheme !== 'devtools');
      if (external.length) throw new Error(`external attempts from the page: ${JSON.stringify(external)}`);
      return external;
    },
  };
}

// Build `--host-resolver-rules`. The two vantages build different values, and this is the
// ONLY module in scripts/gate allowed to build them (asserted by scripts/check-identity.py).
// - Mac vantage (F3's amendment): `MAP <host> <ip>, MAP * ~NOTFOUND, EXCLUDE <ip>` — the
//   catch-all keeps the browser off the internet and off the owner's LAN, and the exclusion
//   must come last because map rules are tried in order (M0 point 5: example.com resolves to
//   net::ERR_NAME_NOT_RESOLVED under this value).
// - Container vantage: the walked one-name mapping.
export function buildResolverRules(host, ip) {
  if (macMode()) {
    if (!net.isIPv4(ip)) exit2(`launchGateBrowser: --resolve-to must be an IPv4 address, got: ${ip}`);
    return `MAP ${host} ${ip}, MAP * ~NOTFOUND, EXCLUDE ${ip}`;
  }
  return ip ? `MAP ${host} ${ip}` : null; // the empty case is the container vantage without a mapping
}

// TOPOFIX-REVIEW F3: the launcher refuses a Mac with a system proxy, because
// --host-resolver-rules does not apply to names a proxy resolves. M0 observed no proxy keys.
const PROXY_KEYS = 'HTTPEnable HTTPSEnable SOCKSEnable ProxyAutoConfigEnable ProxyAutoDiscoveryEnable';
export function refuseSystemProxy() {
  if (process.platform !== 'darwin') return false;
  let raw = '';
  try { raw = execFileSync('scutil', ['--proxy'], { encoding: 'utf8' }); } catch { return false; }
  const on = PROXY_KEYS.split(' ').filter((k) => new RegExp(`^\\s*${k}\\s*=\\s*1\\s*$`, 'm').test(raw));
  if (on.length) exit2(`launchGateBrowser: the Mac runs a system proxy (${on.join(', ')}) and --host-resolver-rules does not apply to proxy-resolved names; turn it off or run the container vantage`);
  return true;
}

function x509OrDie(certPem, what) {
  let cert;
  try { cert = new X509Certificate(certPem); } catch (e) { exit2(`launchGateCertificate: ${what} is not a PEM certificate (${String(e.message || e).slice(0, 120)})`); }
  return cert;
}

export function certDigests(certPem) {
  const cert = x509OrDie(certPem, 'certPem');
  const digest = createHash('sha256').update(cert.raw).digest('hex');
  const spkiB64 = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const subject = cert.subject.replace(/\s+/g, ' ');
  const issuer = cert.issuer.replace(/\s+/g, ' ');
  const cn = (s) => { const m = /CN=([^,\s]+)/.exec(s); return m ? m[1] : ''; };
  return { sha256: digest, spkiB64, subject: dnFold(subject), issuer: dnFold(issuer), subjectCN: cn(subject), issuerCN: cn(issuer) };
}

// F2 (b): the Mac-side validity window of the pinned certificate against the Mac clock.
// The dates' existence and the C-certificate expiry behaviour were observed in M0 (files
// A.crt and C.crt: notAfter 2020-01-02); the comparison itself is clock arithmetic.
export function assertCertValidity(certPem, now = new Date()) {
  const cert = x509OrDie(certPem, 'certPem');
  const notBefore = new Date(cert.validFromDate);
  const notAfter = new Date(cert.validToDate);
  if (now < notBefore || now > notAfter) {
    exit2(`launchGateCertificate: the pinned certificate is not valid at the Mac clock (${now.toISOString()}); validity ${notBefore.toISOString()} .. ${notAfter.toISOString()}`);
  }
  return { notBefore: notBefore.toISOString(), notAfter: notAfter.toISOString(), macClock: now.toISOString() };
}

// F2 (a): the Node pin. `servername` is SNI and the name `checkServerIdentity` verifies;
// `ca` pins the gate certificate as the only trust anchor (a self-signed leaf accepted as
// its own CA). M4 observed `authorized === true` and TLSv1.3 on the fixture. This probe must
// NOT fall back to skipping verification in any branch (phase2_kafbat.py:557 has that
// fallback; TOPOFIX-REVIEW section 5 names it as something not to copy).
export function pinGateCertificate({ host, port, certPem, connectHost }) {
  const target = connectHost || host;
  if (!net.isIPv4(target)) exit2(`pinGateCertificate: connectHost must be an IPv4 address, got: ${target}`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) exit2(`pinGateCertificate: port must be 1..65535, got: ${port}`);
  const info = certDigests(certPem);
  const validity = assertCertValidity(certPem);
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({ host: target, port, servername: host, ca: certPem, rejectUnauthorized: true }, () => {
      settled = true;
      const peer = socket.getPeerCertificate(true);
      // N1 (review): the served leaf's SHA-256 fingerprint must equal the pinned certificate's
      // digest. For the gate's self-signed leaf-as-its-own-CA it is implied by an authorized
      // handshake, but making it explicit is the hook W8's CA-chain variant will need.
      const servedFp = (peer.fingerprint256 || '').replace(/:/g, '').toLowerCase();
      if (servedFp !== info.sha256) {
        const err = new Error(`pinGateCertificate: the served certificate's fingerprint ${peer.fingerprint256 || '(none)'} is not the pinned certificate's sha256 ${info.sha256} (review N1)`);
        socket.destroy();
        reject(err);
        return;
      }
      resolve({
        authorized: socket.authorized,
        authorizationError: null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? '',
        fingerprint256: peer.fingerprint256 || '',
        pinsMatch: true,
        subject: info.subject, issuer: info.issuer, subjectCN: info.subjectCN,
        sha256: info.sha256, spkiB64: info.spkiB64,
        validity,
        serverInfo: { ip: target, port, servername: host },
      });
      socket.destroy();
    });
    socket.setTimeout(10000);
    socket.on('timeout', () => { if (!settled) reject(new Error(`pinGateCertificate: no TLS within 10 s to ${target}:${port}`)); socket.destroy(); });
    socket.on('error', (err) => { if (!settled) reject(err); });
  });
}

// The Mac launch. Fresh profile per story (profile-<pid>, removed by cleanProfile unless the
// story failed), headed by default, `GATE_BROWSER_HEADLESS=1` selects Chrome's new headless
// and the receipt records which (TOPOFIX-DESIGN 3.2). `locale`/`timezoneId`/`viewport` are
// the walked adapter values (m5/phase4-browser.m5.mjs).
export async function launchGateBrowserMac(chromium, { host, resolveTo, outDir, viewport = { width: 1440, height: 900 } }) {
  if (!host) exit2('launchGateBrowser: host is required');
  refuseSystemProxy();
  const rules = buildResolverRules(host, resolveTo);
  const headless = process.env.GATE_BROWSER_HEADLESS === '1';
  const profileDir = `${outDir}/profile-${process.pid}`;
  const context = await chromium.launchPersistentContext(profileDir, {
    channel: 'chrome', headless,
    locale: 'en-US', timezoneId: 'UTC', viewport,
    args: [`--host-resolver-rules=${rules}`],
  });
  let page = context.pages()[0] || await context.newPage();
  return { browser: context, page, mode: 'mac', profileDir, rules, headless, close: () => context.close() };
}

// The container launch: byte-for-byte the stories' walked shape. Nothing in this branch is
// new; the stories only moved their old three lines here.
export async function launchGateBrowserContainer(chromium, { host, resolveTo }) {
  const args = resolveTo ? [`--host-resolver-rules=MAP ${host} ${resolveTo}`] : [];
  const browser = await chromium.launch({ args });
  return { browser, page: null, mode: 'container', profileDir: null, rules: resolveTo ? `MAP ${host} ${resolveTo}` : null, headless: true, close: () => browser.close() };
}

// Entry point every story uses; the switch is exactly the flag block above.
export async function launchGateBrowser(chromium, opts) {
  return macMode() ? launchGateBrowserMac(chromium, opts) : launchGateBrowserContainer(chromium, opts);
}

// Remove the story profile at the end (kept when the story failed for diagnosis).
export function cleanProfile(profileDir, keep) {
  if (!profileDir || keep) return false;
  try { rmSync(profileDir, { recursive: true, force: true }); return true; } catch { return false; }
}

// TOPOFIX-DESIGN 3.5: browser.json beside every manifest binds the screenshot to the browser,
// the path and the certificate. Everything here is readable from the story process itself;
// the agent/launcher may extend it via `extra` (vmIp, macSourceIp). No secret value is ever
// placed in it (passwords and TOTP seeds travel only through the environment).
export async function browserEvidence({ browser, mode, rules, headless, page, cert, extra = {} }) {
  const ev = {
    mode,
    channel: mode === 'mac' ? 'chrome' : 'playwright-bundled-chromium-headless-shell',
    headless,
    hostResolverRules: rules || null,
    ignoreHTTPSErrors: mode !== 'mac', // container vantage fact (walked); the Mac vantage deliberately leaves Chrome's verifier on
    playwright: '1.60.0',
    platform: `${process.platform}-${process.arch}`,
    node: process.version,
  };
  try {
    const b = browser && (browser.browser ? browser.browser() : null);
    if (b && b.version) ev.browserVersion = b.version();
  } catch { ev.browserVersion = ''; }
  if (page) {
    try { ev.userAgent = await page.evaluate(() => navigator.userAgent); } catch { ev.userAgent = ''; }
    try { ev.uaBrands = await page.evaluate(() => (navigator.userAgentData ? navigator.userAgentData.brands.map((b) => `${b.brand} ${b.version}`) : null)); } catch { ev.uaBrands = null; }
    if (mode === 'mac' && /HeadlessChrome/.test(ev.userAgent)) throw new Error('browserEvidence: the browser is a HeadlessChrome build — the formal Mac receipt requires the installed headed Chrome');
  }
  if (cert) ev.cert = {
    authorized: cert.authorized, protocol: cert.protocol, cipher: cert.cipher,
    sha256: cert.sha256, spkiB64: cert.spkiB64, fingerprint256: cert.fingerprint256,
    subject: cert.subject, issuer: cert.issuer,
    validity: cert.validity, server: cert.serverInfo,
    source: 'node tls.connect ca=CERT_FILE servername=SNI rejectUnauthorized=true (M4); CDP Network.getCertificate is NOT a digest source in Chrome 155 (M0 point 6)',
  };
  return Object.assign(ev, extra);
}

// TOPOFIX-DESIGN 3.5, wired: track each page's main-document responses so every shot can bind
// the two assertions (served from the VM address; the served certificate equals the pinned
// one). Response.serverAddr/securityDetails field behaviour observed in M0 point 4. A story
// may attach several sequential pages (X3's viewer and admin pages): `record` uses the most
// recent main-frame response of any attached page, which for a sequential story is the page
// being captured.
export function attachServeTracker(page) {
  const state = { last: null, count: 0 };
  const hook = (p) => {
    p.on('response', (r) => {
      try {
        if (!r.request().isNavigationRequest() || r.request().frame() !== p.mainFrame()) return;
        state.last = r; state.count += 1;
      } catch { /* a detached frame/page: the tracker only serves later shots */ }
    });
  };
  if (page) hook(page);
  return {
    count: () => state.count,
    last: () => state.last,
    attach(newPage) { hook(newPage); return this; },
    async record(expectedIp, pinned, what, asserted) {   // async: Response.serverAddr()/securityDetails() are Promises (Playwright 1.60.0 types.d.ts, review T08)
      if (!state.last) return null;
      asserted.push(await assertServedFrom(state.last, expectedIp, what));
      if (pinned) asserted.push(await assertServedCertificate(state.last, pinned, what));
      return true;
    },
  };
}

// The Mac vantage requires the pinned certificate up front: the story fails closed with the
// launcher's instruction rather than launching an unverifiable browser.
export function requireCertFile() {
  const file = process.env.GATE_CERT_FILE || '';
  if (!file) exit2('GATE_BROWSER_MAC=1 needs GATE_CERT_FILE (the fixture certs/server.crt) so the story can pin the certificate before navigating; the agent/launcher sets it');
  let pem = '';
  try { pem = readFileSync(file, 'utf8'); } catch (e) { exit2(`GATE_CERT_FILE ${file} is not readable: ${String(e.message || e).slice(0, 120)}`); }
  return { file, pem };
}

// F2, interstitial: page.goto rejects with net::ERR_CERT_AUTHORITY_INVALID; the interstitial
// renders AFTER the rejection (M5 run 2 lesson: waitForSelector('#details-button') is
// required before the count check). Selectors and the error-code text are Chrome 155
// observed values (M0 points 2-3; M5 point 1); one Advanced+Proceed covers the same host and
// certificate on every port of it (M0 point 3), so one call per story suffices. No shot is
// taken and no claim is made here about name or date validity (see the module header).
export async function acceptGateCertificate(page, url, { onAssert, onShot } = {}) {
  const decision = { origin: new URL(url).origin, seen: false, error: '', decision: 'none' };
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
  await page.waitForSelector('#details-button', { timeout: 8000 }).catch(() => {});
  if (await page.locator('#details-button').count()) {
    decision.seen = true;
    decision.error = (await page.locator('.error-code').textContent().catch(() => '') || '').trim();
    // The caller's hooks run BEFORE the strict F2 throw so a caller that records evidence can
    // capture the interstitial shot and step even for a rejected code (review N3: U15's
    // unified handling takes the shot before stopping). The stories assert inside onAssert and
    // throw there first; the throw below is then only reached for the same failure.
    if (onAssert) await onAssert(decision);
    if (onShot) await onShot(decision);
    // The amended claim (F2): the code proves only that the chain does not end in a trusted
    // root. It is still the expected code — AUTHORITY_INVALID outranks the name/date codes,
    // so any OTHER code here means the fixture served a different defect (name mismatch
    // alone, expired date) and the story must stop rather than proceed silently.
    if (!/ERR_CERT_AUTHORITY_INVALID/.test(decision.error)) {
      throw new Error(`certificate interstitial shows ${decision.error || 'no code'}; expected net::ERR_CERT_AUTHORITY_INVALID (F2: the code does not rank below a name or date error, and a different code means a different defect)`);
    }
    await page.click('#details-button');
    await Promise.all([page.waitForLoadState('load'), page.click('#proceed-link')]).catch(() => {});
    await page.waitForLoadState('load').catch(() => {});
    decision.decision = 'proceed';
  } else {
    // No interstitial: an unexpected state for a trust-nothing profile (M0/M5 always saw the
    // warning). The caller records it; the story's own assertions decide the verdict.
    decision.decision = 'no-interstitial';
  }
  return decision;
}

// TOPOFIX-DESIGN 3.5/F6: the shot's main document came from the VM's NIC address, never from
// a host-agent forward (which would be 127.0.0.1/::1). Response.serverAddr() is Playwright's
// {ipAddress, port}; M0 point 4 observed it filled under the resolver rule.
export async function assertServedFrom(resp, expected, what) {
  if (!resp) throw new Error(`${what}: no main-document response to assert the server address on`);
  let addr;
  try { addr = await resp.serverAddr(); } catch (e) { throw new Error(`${what}: Response.serverAddr() unavailable: ${String(e.message || e).slice(0, 120)}`); }
  if (!addr || !addr.ipAddress) throw new Error(`${what}: Response.serverAddr() empty`);
  if (addr.ipAddress === '127.0.0.1' || addr.ipAddress === '::1') {
    throw new Error(`${what}: served from ${addr.ipAddress}:${addr.port || '?'} — that is a host-agent forward, not the VM address ${expected}`);
  }
  if (expected && addr.ipAddress !== expected) {
    throw new Error(`${what}: served from ${addr.ipAddress}:${addr.port || '?'}, expected ${expected}`);
  }
  return `served from ${addr.ipAddress}:${addr.port || '?'} (Response.serverAddr)`;
}

// F2 (c), the digest source: the served certificate's fields compared with the pinned one.
// Response.securityDetails() gives issuer, subjectName, protocol and the validity dates; M0
// point 4 observed exactly those fields populated on the Mac. Equal subjectAnd issuer plus
// the Node pin's fingerprint close the "what did Chrome actually receive" question without
// CDP Network.getCertificate (M0 point 6: it has no certificates to give in Chrome 155).
export async function assertServedCertificate(resp, pinned, what) {
  if (!resp) throw new Error(`${what}: no main-document response to assert securityDetails on`);
  let details;
  try { details = await resp.securityDetails(); } catch (e) { throw new Error(`${what}: Response.securityDetails() unavailable: ${String(e.message || e).slice(0, 120)}`); }
  if (!details || !details.subjectName) throw new Error(`${what}: Response.securityDetails() empty (the story must be in mac mode against a fixture certificate)`);
  const wrong = [];
  if (details.subjectName && pinned.subject && !dnFold(pinned.subject).includes(dnFold(details.subjectName))) wrong.push(`subject ${details.subjectName}`);
  if (details.issuer && pinned.issuer && !dnFold(pinned.issuer).includes(dnFold(details.issuer))) wrong.push(`issuer ${details.issuer}`);
  if (wrong.length) throw new Error(`${what}: the browser received a different certificate than the pinned one (${wrong.join(', ')}; expected subject/issuer of certs/server.crt)`);
  const valid = { protocol: details.protocol || '', subject: details.subjectName, issuer: details.issuer || '', validFrom: details.validFrom || '', validTo: details.validTo || '' };
  return `TLS ${valid.protocol || '?'}, subject ${valid.subject}, issuer ${valid.issuer}, valid to ${valid.validTo || '?'} (Response.securityDetails)`;
}