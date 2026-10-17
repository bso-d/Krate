// Mac-side probes for the Phase 4c W rows (TOPOFIX-REVIEW F6; run by scripts/gate/mac/agent.mjs).
//
// `sweep`  — from the Mac, a full TCP connect sweep of ports 1-65535 against the VM's vzNAT
//            address, every probe classified (open / refused / rejected / timeout), a
//            per-port spot outcome table for the ports the row needs decided (the control
//            port 111 first among them), a targeted IPv6 pass on the guest's lima0 address (the
//            GLOBAL one without a zone; a link-local only with the Mac's owning interface as its
//            zone), and — when --cert is
//            given — the Node TLS pin on --port. TCP only: none of the product's published
//            ports is UDP; the guest's UDP listeners are printed beside the row by the
//            runner (F6). Licence: the M4 hand-walk ran this method live (nc -z -G 1,
//            xargs -P 64) and observed open exactly {22, 80, 443, 3443, 9092, 9093} with 111
//            closed; M2 observed the Mac-side interface and the SSH reach.
// `clientaddr` — from the Mac, one request to the public name for the W6 row: TLS verified
//            against the pinned certificate (never -k), the forged source address
//            (X-Forwarded-For 203.0.113.9) and the row's User-Agent carried so the guest's
//            proxy log names the real source. M4 observed the 200 answer and the logged
//            remote_addr being the Mac's vmnet address.
//
// Output: one `RESULT <row> rc=<n>` line, plus a JSON file and its sha256 in --out; the agent
// ships the whole directory back into the guest. No secret value ever appears in the output.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import net from 'node:net';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

function die(msg, rc = 2) { console.error(`probe(${process.argv[2] || ''}): ${msg}`); process.exit(rc); }

const args = {};
const pairs = process.argv.slice(3);
for (let i = 0; i < pairs.length; i++) {
  if (!pairs[i].startsWith('--')) continue;
  args[pairs[i].slice(2)] = pairs[i + 1] ?? '';
}
const sub = process.argv[2] || die('subcommand sweep|clientaddr is required');
const OUT = args.out || die('--out DIR is required');
mkdirSync(OUT, { recursive: true });
const ip = args.ip || die('--ip is required');
if (!net.isIPv4(ip)) die(`--ip must be an IPv4 address, got ${ip}`);
const host = args.host || die('--host is required');

// Node connect error -> the row's outcome name (F6: record refused (RST) and rejected
// (ICMP admin-prohibited; EHOSTUNREACH by platform — M3 observed an icmp-port-unreachable
// REJECT landing as a socket error on this same mechanism) separately.
function outcomeOf(code) {
  switch (code) {
    case 'ECONNREFUSED': return 'refused';
    case 'EHOSTUNREACH': case 'ENETUNREACH': case 'EHOSTDOWN': case 'EPERM': return 'rejected';
    case 'ETIMEDOUT': case 'ECONNRESET': case 'ECONNABORTED': return 'timeout';
    case 'EADDRNOTAVAIL': case 'ENOTSUP': case 'EINVAL': case 'ENXIO': return 'no-route-or-scope';
    default: return `other-${code || 'unknown'}`;
  }
}
function connectOnce(targetAddress, port, family, timeoutMs) {
  return new Promise((res) => {
    const sock = net.connect({ host: targetAddress, port, family });
    let done = false;
    const finish = (outcome) => { if (!done) { done = true; sock.destroy(); res({ port, outcome }); } };
    sock.setTimeout(timeoutMs, () => finish('timeout'));
    sock.on('connect', () => finish('open'));
    sock.on('error', (e) => finish(outcomeOf(e.code)));
  });
}

async function sweepAll(target, timeoutMs, concurrency) {
  const results = new Map();
  let idx = 1;
  let completed = 0;
  const worker = async () => {
    for (;;) {
      const p = idx++; if (p > 65535) return;
      const r = await connectOnce(target, p, 4, timeoutMs);
      results.set(p, r.outcome);
      completed += 1;
      if (completed % 8192 === 0) process.stdout.write(`probe: swept ${completed}/65535\n`);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return results;
}

async function subSweep() {
  const concurrency = Number(args.concurrency || 64) || 64;
  const timeoutMs = Number(args.timeout || 700) || 700;
  const spot = (args.spot || '111').split(',').map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
  const t0 = Date.now();
  const all = await sweepAll(ip, timeoutMs, concurrency);
  const open = [];
  const counts = { open: 0, refused: 0, rejected: 0, timeout: 0, noRouteScope: 0, other: 0 };
  for (const outcome of all.values()) {
    if (outcome === 'open') { counts.open += 1; }
    else if (outcome === 'refused') { counts.refused += 1; }
    else if (outcome === 'rejected') { counts.rejected += 1; }
    else if (outcome === 'timeout') { counts.timeout += 1; }
    else if (outcome === 'no-route-or-scope') { counts.noRouteScope += 1; }
    else { counts.other += 1; }
  }
  for (const [p, outcome] of all) if (outcome === 'open') open.push(p);
  const spotOut = new Map();
  for (const p of spot) spotOut.set(p, { port: p, outcome: all.get(p) || 'not-swept', inSpot: true });
  for (const p of open) if (!spotOut.has(p)) spotOut.set(p, { port: p, outcome: 'open', inSpot: false });
  const report = {
    row: 'W5', ip, host,
    swept: { from: 1, to: 65535, concurrency, timeoutMs, tcpOnly: true, seconds: Math.round((Date.now() - t0) / 100.0) / 10 },
    open: open.sort((a, b) => a - b),
    counts,
    spot: [...spotOut.values()].sort((a, b) => a.port - b.port),
    positives: [],
  };
  // The Node pin on the HTTPS port, when the agent passed the certificate (M4's probe: a
  // self-signed leaf accepted as its own CA, name check on; the fallback-to-no-verification
  // shape of phase2_kafbat.py:557 is deliberately NOT copied).
  if (args.cert) {
    const port = Number(args.port || 443);
    try {
      const { pinGateCertificate } = await import(join(HERE, '../browser-launch.mjs'));
      const cert = readFileSync(resolvePath(args.cert), 'utf8');
      const pin = await pinGateCertificate({ host, port, certPem: cert, connectHost: ip });
      report.cert = {
        authorized: pin.authorized, protocol: pin.protocol, sha256: pin.sha256,
        subject: pin.subjectCN || pin.subject, server: pin.serverInfo, validity: pin.validity,
      };
      report.positives.push(`port ${port} tls authorized=${pin.authorized} protocol=${pin.protocol}`);
      if (!pin.authorized) die(`W5: the TLS pin on ${ip}:${port} failed authorization (${pin.authorizationError})`, 1);
    } catch (e) {
      report.cert = { error: String(e.message || e).slice(0, 300) };
      die(`W5: the TLS pin failed: ${String(e.message || e).slice(0, 200)}`, 1);
    }
  }
  // Targeted IPv6 when the guest carries a link-local/global address on lima0 (M4 probed 22,
  // 80, 443, 111, 3443, 9092; those [::] listeners are docker-proxy's, whose zone behaviour
  // lab8 N11a recorded: 22 open, published ports refused). A zone is valid on an fe80::/10
  // address only; a global address with a `%iface` suffix is refused (TOPOFIX2 PRE-6).
  if (args.v6) {
    const [ll, iface] = String(args.v6).split('%');
    const linkLocal = /^fe[89ab][0-9a-f]:/i.test(ll);
    if (!net.isIPv6(ll) || (linkLocal && !iface) || (!linkLocal && iface)) die(`--v6 must be a global <ipv6> without a zone (the agent passes the guest's lima0 GLOBAL address from the hello's vm_g6) or an fe80::/10 address with its <mac-iface> zone (M4 probed the link-local %bridge100), got ${args.v6}`);
    const target = iface ? `${ll}%${iface}` : ll;
    // The IPv4 open set carries the runtime-published ports (including fixture overrides).
    // Explicit ports add probes; they must never replace that coverage or the controls.
    const extraV6Ports = String(args['v6-ports'] || '').split(',').map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
    const v6Ports = [...new Set([...open, 22, 80, 443, 111, 3443, 9092, 9093, ...extraV6Ports])].sort((a, b) => a - b);
    const v6 = [];
    for (const p of v6Ports) {
      const r = await connectOnce(target, p, 6, Math.max(timeoutMs, 3000));
      v6.push({ port: p, outcome: r.outcome });
    }
    report.v6 = { addressClass: args['v6-class'] || (linkLocal ? 'link-local' : 'global'), address: target, ports: v6 };   // S6: the class is recorded, not assumed
    report.positives.push(`v6 ${report.v6.addressClass} ${target} open=[${v6.filter((x) => x.outcome === 'open').map((x) => x.port).join(',') || 'none'}]`);
  }
  const j = JSON.stringify(report, null, 2);
  writeFileSync(join(OUT, 'w5-result.json'), j + '\n');
  writeFileSync(join(OUT, 'w5-result.sha256'), `${createHash('sha256').update(j).digest('hex')}  w5-result.json\n`);
  console.log(`RESULT W5 rc=0 open=${counts.open} refused=${counts.refused} rejected=${counts.rejected} timeout=${counts.timeout} seconds=${report.swept.seconds} tcp_only=true open_set=[${report.open.join(',')}]${report.v6 ? ` v6_open=[${report.v6.ports.filter((p) => p.outcome === 'open').map((p) => p.port).join(',')}]` : ' v6=not-run'}`);
}

async function subClientaddr() {
  const port = Number(args.port || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) die(`--port must be 1..65535, got ${args.port}`);
  const ua = args.ua || die('--ua is required (the row nonce the guest log greps for)');
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(ua)) die('--ua must be plain tokens (it lands in a log the runner parses)');
  const xff = args.xff || '203.0.113.9';
  const certPath = args.cert || die('--cert FILE is required: W6 verifies TLS against the pinned certificate, never -k (M4)');
  const url = `https://${host}${port === 443 ? '' : ':' + port}/identity/realms/krate/.well-known/openid-configuration`;
  const report = {
    row: 'W6', ip, host, port, ua, xff, url,
    resolve: `${host}:${port}:${ip}`, cacert: 'agent-provided certs/server.crt', httpsOnly: true,
    ipv4Only: true, // the IPv6 docker-proxy path is the lab8 N11a asymmetry; the row states it rather than asserting it
  };
  const bodyPath = join(OUT, 'w6-discovery.json');
  try {
    const { stdout } = await execFileP('curl', [
      '--silent', '--show-error', '--max-time', '20', '--cacert', certPath,
      '--resolve', `${host}:${port}:${ip}`,
      '--user-agent', ua, '--header', `X-Forwarded-For: ${xff}`, '--header', 'Accept: application/json',
      '--output', bodyPath, '--write-out', '%{http_code}',
      url,
    ], { timeout: 25000 });
    report.status = Number(stdout);
    report.body_bytes = statSync(bodyPath).size;
    if (report.status !== 200) die(`W6: discovery answered HTTP ${report.status}, expected 200 from the pinned channel (M4 observed 200)`, 1);
    report.issuer = JSON.parse(readFileSync(bodyPath, 'utf8')).issuer || '';
    report.positives = [`discovery 200, issuer ${report.issuer}`];
  } catch (e) {
    report.error = String(e.message || e).slice(0, 300);
    writeFileSync(join(OUT, 'w6-result.json'), JSON.stringify(report, null, 2) + '\n');
    die(`W6: the request failed: ${report.error}`, 1);
  }
  const j = JSON.stringify(report, null, 2);
  writeFileSync(join(OUT, 'w6-result.json'), j + '\n');
  console.log(`RESULT W6 rc=0 status=${report.status} issuer=${report.issuer} ua=${ua} xff=${xff} resolve=${report.resolve} (the runner in the guest asserts the proxy log's remote_addr == mac_src_ip)`);
}

if (sub === 'sweep') await subSweep();
else if (sub === 'clientaddr') await subClientaddr();
else die(`unknown subcommand ${sub} (sweep|clientaddr)`);
