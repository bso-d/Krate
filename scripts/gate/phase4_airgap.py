#!/usr/bin/env python3
"""Air-gap rows AG1-AG5 of the identity gate (a formal run on a bundle host).

A receipt must not claim an offline run the host did not have.  On a bundle host
(the edition directory is an installed bundle, no tracked git) the gate proves,
from before its first row to after its last:

  AG1  the air gap is up before the first row: the krate-airgap unit is enabled
       and active, the reject chains and their catch-all jumps exist (FORWARD
       jumps to DOCKER-USER before DOCKER-FORWARD), every non-loopback IPv4
       resolver is covered, and every probe is refused (host HTTP, host DNS, host
       IPv6, container HTTP, container DNS on the default bridge, container DNS
       on a user-defined network, which is the embedded resolver path the
       product containers use);
  AG2  the same, after the last row, and the gap was not rebuilt in between
       (same boot id, same unit start time, same rule text, reject counters and
       jump-rule counters not lower than at AG1);
  AG3  no image was pulled in the run: a `docker events` subscription opened at the
       window start with `--since <window start>` (it replays only the daemon's ring
       from that second on, so a pull before the window is not read), kept alive
       across a daemon restart by a small supervisor (`watch-loop`), with a control
       event (a throw-away volume create) seen at the start and at the end, so a
       silent subscription cannot read as "0 pulls".  One instant stays unprovable and
       the row does not claim it: a pull that the ending daemon logged in the moment
       between the stream's last delivered event and its close is lost with that daemon's
       memory; AG3 states exactly the events its segments saw;
  AG4  the offline install of this host was proven offline when it was made: the
       install record written by `install-record begin|watch|end` exists, is
       complete, is bound to this air-gap script and to this bundle (the digests
       of krate, docker-compose.yml, .env.template, nginx.conf, images.lock.tsv),
       and says 0 pulls and 0 public-name lookups by containers during the install;
  AG5  the product's containers made no outbound attempt in the run window: the
       KRATE-AIRGAP-FWD reject counter did not move, and dockerd logged no
       "failed to query external DNS server" for a public-looking name (two or more
       labels, a configured search domain not counted).  Single-label names (a
       compose service asked for after it stopped) are listed but do not fail the
       row.  The embedded-DNS probe's own lookups must be visible in the journal (a
       control), or the count is blind.  A failed pull is not counted here: it is
       neither a daemon event nor a container lookup.

On the Mac (--host-kind darwin) and on a Linux git checkout (--host-kind checkout)
every row is NOT_RUN with the reason; the air gap is a property of the VM
provisioning, never PASS from a host that cannot show it.  On a bundle host a
missing air gap, a probe that cannot run, a missing tool, an unreadable journal or
a missing install record is FAIL with the reason, never PASS.

What the probes send.  Nothing on a side whose reject rule is missing (the OUTPUT
jump and its chain for the host and for the embedded resolver, which forwards from
the host side; the DOCKER-USER jump and its chain for container traffic): that side
is FAIL and is not probed, so a missing gap is not probed over the owner's network.
Otherwise: host: one `curl -q -m 5` request to http://1.1.1.1/ (a TCP connection and
`GET /`), one `getent hosts download.docker.com` (a DNS lookup through the host's
resolver), and, only when `ip -6 route get` shows a route, one `curl -q -6 -m 5` to
http://[2606:4700:4700::1111]/; containers (the bundle's python image, `--pull never`):
one TCP connect to 1.1.1.1:80 and one getaddrinfo of download.docker.com, the DNS one
on the default bridge and on a throw-away user-defined bridge.  Bounds: curl 5 s, getent
6 s, the container probes 6 s inside the container and 15 s outside; no probe runs
longer.  curl runs without proxy variables and without a curlrc (curl reads http_proxy
and friends: an unreachable proxy would answer rc 7 for a probe that never left the host).

Docker facts the design rests on (Docker Engine 29.9.0, moby tag docker-v29.9.0, read
at the source): the daemon keeps only its last 256 events in memory, of all types, and
`--since`/`--until` replay that buffer filtered afterwards (daemon/events/events.go:
eventsLimit = 256, loadBufferedEvents: nothing is replayed only when BOTH are zero, so
`--until` alone replays the whole ring); the buffer is created at daemon start and is
empty after a restart; a pull event is logged only after a pull succeeded
(daemon/internal/distribution/pull.go `if err == nil`, daemon/containerd/image_pull.go),
so a failed attempt leaves no event and a count of "0 pulls" from a replay of a long
window is not evidence.  A daemon restart ends the CLI's event stream (cli/command/system/
events.go returns on io.EOF): the supervisor writes a detach marker, waits for the new
daemon, writes an attach marker with the number of events (all types) the new daemon's ring
holds since the window start, and re-subscribes with the same --since, so a pull between the
restart and the re-attach is replayed.  A ring that held 256 events at the re-attach may
have dropped older ones: that segment cannot prove 0 pulls and AG3 is FAIL.  The daemon
does not touch the rules of DOCKER-USER and keeps FORWARD -> DOCKER-USER before
DOCKER-FORWARD at every start (daemon/libnetwork/firewall_linux.go, TestUserChain goldens).
Of the gate's rows only V24 (phase4_perses.py) restarts the daemon (`systemctl restart
docker`, root or sudo -n, live-restore off).

Output: one `id<TAB>result<TAB>evidence` line per row on stdout (the runner records
them with phase4_ingest); progress goes to stderr.  Exit 0 when no row failed, 1
otherwise.  Python 3.9 compatible, standard library only.

  phase4_airgap.py before --host-kind bundle|checkout|darwin --state DIR --edition-dir DIR --mon-dir DIR
  phase4_airgap.py after  --host-kind ...                     (same options; add --exit-path from finish())
  phase4_airgap.py install-record begin|watch|end [--state DIR] [--record FILE] [--edition-dir DIR --mon-dir DIR]
  phase4_airgap.py watch-loop --events-file F --err-file F --since T --until T   (started by the steps above)
"""
import argparse
import hashlib
import json
import math
import os
import re
import shlex
import signal
import subprocess
import sys
import time

UNIT = 'krate-airgap.service'
DEFAULT_SCRIPT = '/usr/local/sbin/krate-airgap'
DEFAULT_RECORD = '/var/lib/krate-airgap/install-record.json'
DEFAULT_RECORD_STATE = '/var/lib/krate-airgap'
DEFAULT_BOOT_ID = '/proc/sys/kernel/random/boot_id'
DEFAULT_RESOLV = ('/etc/resolv.conf', '/run/systemd/resolve/resolv.conf')
CHAIN_OUT = 'KRATE-AIRGAP-OUT'
CHAIN_FWD = 'KRATE-AIRGAP-FWD'
HTTP4 = ('1.1.1.1', 80)
HTTP6 = ('2606:4700:4700::1111', 80)
PROBE_NAME = 'download.docker.com'
CONTROL_PREFIX = 'krate-airgap-control-'
NET_PREFIX = 'krate-airgap-probe-'
NET_LABEL = 'krate.gate=airgap-probe'
WATCH_SECONDS = 2 * 3600  # bounded backstop: far longer than any receipt run, so a hard-killed run orphans a
                          # supervisor for at most this long instead of a day
WATCH_TICK = 2            # seconds between the supervisor's own state-file checks (SF3: it must not outlive its run)
RESOLVER_ERROR = 'failed to query external DNS server'
RING_LIMIT = 256  # daemon/events/events.go eventsLimit
DNS_SECONDS = 6   # inside the container probe
GETENT_SECONDS = 6
CONTAINER_PROBE_SECONDS = 15
PRODUCT_FILES = ('krate', 'docker-compose.yml', '.env.template', 'nginx.conf', 'kafbat.yml', 'images.lock.tsv')
RECORD_FORMAT = 1
ROWS_BEFORE = ('AG1', 'AG4')
ROWS_AFTER = ('AG2', 'AG3', 'AG5')
ALL_ROWS = ('AG1', 'AG2', 'AG3', 'AG4', 'AG5')
PROBE_ORDER = ('host_http', 'host_dns', 'host_http6', 'container_http', 'container_dns', 'container_dns_embedded')

# The container probes print one sentinel line, so a crashed interpreter or a failed
# `docker run` is "cannot run", never "blocked" (the W4 rule: a probe is conclusive only
# through its own sentinel).
SCRIPT_HTTP = (
    'import socket, sys\n'
    'try:\n'
    '    socket.create_connection(("%s", %d), 5).close()\n'
    'except OSError as e:\n'
    '    print("AGPROBE blocked errno=%%s %%s" %% (e.errno, type(e).__name__)); sys.exit(3)\n'
    'print("AGPROBE reached"); sys.exit(0)\n' % HTTP4)
SCRIPT_DNS = (
    'import os, socket, sys, threading\n'
    'out = []\n'
    'def work():\n'
    '    try:\n'
    '        out.append(("ok", socket.getaddrinfo("%s", 443)[0][4][0]))\n'
    '    except OSError as e:\n'
    '        out.append(("err", "errno=%%s %%s" %% (e.errno, type(e).__name__)))\n'
    'worker = threading.Thread(target=work, daemon=True)\n'
    'worker.start()\n'
    'worker.join(%d)\n'
    'if not out:\n'
    '    print("AGPROBE blocked timeout (no answer in %d s)"); sys.stdout.flush(); os._exit(3)\n'
    'if out[0][0] == "ok":\n'
    '    print("AGPROBE resolved %%s" %% out[0][1]); sys.exit(0)\n'
    'print("AGPROBE blocked %%s" %% out[0][1]); sys.exit(3)\n' % (PROBE_NAME, DNS_SECONDS, DNS_SECONDS))


# ───────────────────────────── process plumbing ─────────────────────────────
class Ctx:
    """Everything that touches the host goes through run(): tools are found on PATH, so a
    missing tool is rc 127 and a test can stub every one of them."""

    def __init__(self, args):
        self.args = args
        self.root = hasattr(os, 'geteuid') and os.geteuid() == 0

    @staticmethod
    def probe_env():
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
        env['LC_ALL'] = 'C'
        return env

    def run(self, argv, timeout=20, root=False, clean_env=False):
        """(rc, combined output).  rc 124 timeout, 125 other start failure, 126 not executable,
        127 not found."""
        cmd = list(argv)
        if root and not self.root:
            cmd = ['sudo', '-n'] + cmd
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                                  env=self.probe_env() if clean_env else None, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            return 127, '%s: command not found' % cmd[0]
        except PermissionError:
            return 126, '%s: permission denied' % cmd[0]
        except subprocess.TimeoutExpired as exc:
            partial = (exc.stdout or b'').decode('utf-8', 'replace') if isinstance(exc.stdout, bytes) else ''
            return 124, partial or '%s: no answer within %d s' % (cmd[0], timeout)
        except OSError as exc:
            return 125, '%s: %s' % (cmd[0], exc)
        return proc.returncode, proc.stdout.decode('utf-8', 'replace')


def log(message):
    sys.stderr.write('%s phase4_airgap: %s\n' % (time.strftime('%H:%M:%S', time.gmtime()), message))
    sys.stderr.flush()


def utc(epoch=None):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if epoch is None else epoch))


def first_line(text, limit=120):
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(65536), b''):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def read_text(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return None


# ───────────────────────────── pure parsers and classifiers ─────────────────────────────
def parse_rules(text):
    """The `-A` lines of `iptables -S <chain>` as token lists."""
    rules = []
    for line in (text or '').splitlines():
        if not line.startswith('-A '):
            continue
        try:
            rules.append(shlex.split(line))
        except ValueError:
            rules.append(line.split())
    return rules


def option(rule, flag):
    if flag in rule:
        index = rule.index(flag)
        if index + 1 < len(rule):
            return rule[index + 1]
    return None


def has_catchall(rules, chain, target):
    return any(rule == ['-A', chain, '-j', target] for rule in rules)


def last_target(rules, chain):
    own = [rule for rule in rules if rule[:2] == ['-A', chain]]
    return option(own[-1], '-j') if own else None


def covers(rules, chain, target, ip, proto):
    return any(rule[:2] == ['-A', chain] and option(rule, '-d') == ip + '/32' and option(rule, '-p') == proto
               and option(rule, '--dport') == '53' and option(rule, '-j') == target for rule in rules)


def resolvers_from(paths):
    """Non-loopback IPv4 resolvers of the given resolv.conf files, as airgap.sh derives them
    (nameserver lines whose address is neither 127.* nor IPv6), and the IPv6 ones for the evidence."""
    v4, v6 = set(), set()
    for path in paths:
        text = read_text(path)
        for line in (text or '').splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == 'nameserver':
                if ':' in fields[1]:
                    if fields[1] not in ('::1',):
                        v6.add(fields[1])
                elif not fields[1].startswith('127.'):
                    v4.add(fields[1])
    return sorted(v4), sorted(v6)


def search_domains_from(paths):
    """The `search`/`domain` names of the resolv.conf files: a container asking for `loki` is sent as `loki.<domain>.`
    when the host has a search domain, which is still a service name, not a public one."""
    domains = set()
    for path in paths:
        for line in (read_text(path) or '').splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] in ('search', 'domain'):
                domains.update(d.strip('.').lower() for d in fields[1:] if d.strip('.'))
    return sorted(domains)


def parse_counters(text):
    """{target: packets} summed over the rows of `iptables -L <chain> -v -n -x`, None when no row parsed."""
    totals = {}
    for line in (text or '').splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].isdigit() and fields[1].isdigit():
            totals[fields[2]] = totals.get(fields[2], 0) + int(fields[0])
    return totals or None


def classify_curl(rc):
    if rc == 0:
        return 'leak', 'connected and was answered (curl rc 0)'
    if rc == 7:
        return 'blocked', 'refused (curl rc 7)'
    if rc == 28:
        return 'blocked', 'timed out (curl rc 28)'
    if rc in (124, 125, 126, 127):
        return 'cannot', 'curl did not run (rc %d)' % rc
    return 'cannot', 'curl rc %d is neither a refusal (7) nor a timeout (28): a connection may have been made' % rc


def classify_getent(rc, out):
    if rc == 0:
        return 'leak', 'resolved %s (getent rc 0)' % (first_line(out, 60) or 'a name')
    if rc == 2:
        return 'blocked', 'not resolved (getent rc 2)'
    if rc == 124:
        return 'blocked', 'timed out (no answer in %d s: the resolver is silent)' % GETENT_SECONDS
    return 'cannot', 'getent did not run or answered rc %d: %s' % (rc, first_line(out, 60))


def classify_sentinel(rc, out):
    for line in out.splitlines():
        if line.startswith('AGPROBE '):
            word = line.split()[1] if len(line.split()) > 1 else ''
            if word in ('reached', 'resolved'):
                return 'leak', line.strip()[:80]
            if word == 'blocked':
                return 'blocked', line.strip()[:80]
    return 'cannot', 'no AGPROBE answer (docker rc %d): %s' % (rc, first_line(out, 80))


QUESTION = re.compile(r'question="?;([^\\"]*)')


def lookup_names(lines):
    """{name: count} of the question names of dockerd's "failed to query external DNS server" lines.
    The journal keeps the question as `;name.<backslash>tIN<backslash>t A`."""
    names = {}
    for line in lines:
        match = QUESTION.search(line)
        name = match.group(1) if match else '?'
        names[name] = names.get(name, 0) + 1
    return names


def split_lookups(names, search=()):
    """(public-looking, single-label): a name of two or more labels could leave the site; a single label (or a single
    label plus one of the host's search domains) is a compose service asked for after it stopped."""
    def labels(name):
        return [x for x in name.rstrip('.').lower().split('.') if x]

    def service_name(name):
        parts = labels(name)
        if len(parts) == 1:
            return True
        for domain in search:
            tail = labels(domain)
            if tail and len(parts) == len(tail) + 1 and parts[1:] == tail:
                return True
        return False
    public = {n: c for n, c in names.items() if n == '?' or not service_name(n)}
    single = {n: c for n, c in names.items() if n not in public}
    return public, single


def counted(names, limit=6):
    if not names:
        return 'none'
    items = sorted(names.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ', '.join('%s x%d' % (n, c) for n, c in items[:limit])
    return shown + (' (+%d more)' % (len(items) - limit) if len(items) > limit else '')


def parse_stream(text):
    """(events, markers, bad) of the watcher's file.  events: [(type, action, actor id, name attribute)] of the daemon's
    JSON lines (--format '{{json .}}'), de-duplicated (a re-attach replays the ring from the window start);
    markers: the supervisor's own lines {Type: airgap, Action: attach|detach, ...}; bad: unreadable lines."""
    events, markers, seen, bad = [], [], set(), 0
    for line in (text or '').splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(doc, dict):
            bad += 1
            continue
        if doc.get('Type') == 'airgap':
            markers.append(doc)
            continue
        actor = doc.get('Actor')
        if not isinstance(actor, dict):
            actor = {}
        attributes = actor.get('Attributes')
        if not isinstance(attributes, dict):
            attributes = {}
        event = (str(doc.get('Type', '')), str(doc.get('Action') or doc.get('status') or ''),
                 str(actor.get('ID') or doc.get('id') or ''), str(attributes.get('name', '')))
        key = (doc.get('timeNano'),) + event
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
    return events, markers, bad


def parse_events(text):
    """[(type, action, actor id, name attribute)] of the daemon's JSON lines, and the number of unreadable lines."""
    events, _, bad = parse_stream(text)
    return events, bad


def read_lock(path):
    """{source_reference: runtime_reference} of an images.lock.tsv (header skipped)."""
    text = read_text(path)
    rows = {}
    for line in (text or '').splitlines()[1:]:
        fields = line.split('\t')
        if len(fields) >= 2 and fields[0]:
            rows[fields[0]] = fields[1]
    return rows


def template_value(path, key):
    text = read_text(path)
    value = None
    for line in (text or '').splitlines():
        if line.startswith(key + '='):
            value = line.split('=', 1)[1].strip()
    return value


# ───────────────────────────── host facts ─────────────────────────────
def pick_image(ctx):
    """The container probe image: the bundle's python image (LOG_DISCOVERY_IMAGE of monitoring/.env.template,
    mapped through images.lock.tsv when the template still holds the source reference; else the lock's
    python: row).  Every kraft and epc bundle carries MONITOR_IMAGES (Makefile:35,210-211), which hold it."""
    args = ctx.args
    lock = read_lock(os.path.join(args.edition_dir, 'images.lock.tsv'))
    candidates = []
    value = template_value(os.path.join(args.mon_dir, '.env.template'), 'LOG_DISCOVERY_IMAGE')
    if value:
        candidates.append(lock.get(value, value))
    candidates += [runtime for source, runtime in sorted(lock.items()) if source.startswith('python:')]
    seen = []
    for image in candidates:
        if image in seen:
            continue
        seen.append(image)
        rc, _ = ctx.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], timeout=30)
        if rc == 0:
            return image, 'image %s' % image
    if not candidates:
        return None, 'no python image named by monitoring/.env.template (LOG_DISCOVERY_IMAGE) or images.lock.tsv'
    return None, 'the python image %s is not on this host (docker image inspect failed)' % candidates[0]


def product_digests(edition_dir):
    """{file: sha256} of the product files of the installed edition that the bundle ships (Makefile bundle target): the
    CLI, the compose file, the env template, nginx.conf, kafbat.yml (epc) and the image lock."""
    digests = {}
    for name in PRODUCT_FILES:
        digest = sha256_file(os.path.join(edition_dir, name))
        if digest:
            digests[name] = digest
    return digests


def read_boot_id(ctx):
    text = read_text(ctx.args.boot_id_file)
    return text.strip() if text and text.strip() else None


def unit_since(ctx, unit=UNIT):
    rc, out = ctx.run(['systemctl', 'show', unit, '-p', 'ActiveEnterTimestamp'], timeout=15)
    if rc != 0:
        return None
    for line in out.splitlines():
        if line.startswith('ActiveEnterTimestamp='):
            return line.split('=', 1)[1].strip() or None
    return None


def iptables(ctx, *args):
    return ctx.run(['iptables'] + list(args), timeout=20, root=True)


def rules_fingerprint(ctx):
    parts = []
    for chain in ('OUTPUT', 'DOCKER-USER', CHAIN_OUT, CHAIN_FWD):
        rc, out = iptables(ctx, '-S', chain)
        if rc != 0:
            return None, 'iptables -S %s rc %d: %s' % (chain, rc, first_line(out, 60))
        parts.append('%s\n%s' % (chain, '\n'.join(l for l in out.splitlines() if l.startswith('-'))))
    return hashlib.sha256('\n'.join(parts).encode('utf-8')).hexdigest(), ''


def read_counters(ctx):
    """({'OUT': {...}, 'FWD': {...}} | None, reason).  Unreadable counters are a reason, not a zero."""
    result = {}
    for key, chain in (('OUT', CHAIN_OUT), ('FWD', CHAIN_FWD)):
        rc, out = iptables(ctx, '-L', chain, '-v', '-n', '-x')
        if rc != 0:
            return None, 'iptables -L %s rc %d: %s' % (chain, rc, first_line(out, 60))
        totals = parse_counters(out)
        if totals is None or 'REJECT' not in totals:
            return None, 'iptables -L %s -v -n -x gave no REJECT row with a packet count' % chain
        result[key] = totals
    return result, ''


def read_jump_counters(ctx):
    """({'OUT': n, 'FWD': m} | None, reason): packets that matched the rules of OUTPUT that jump to KRATE-AIRGAP-OUT and the
    rules of DOCKER-USER that jump to KRATE-AIRGAP-FWD.  A rule deleted and added again with the same text starts at 0."""
    result = {}
    for key, chain, target in (('OUT', 'OUTPUT', CHAIN_OUT), ('FWD', 'DOCKER-USER', CHAIN_FWD)):
        rc, out = iptables(ctx, '-L', chain, '-v', '-n', '-x')
        if rc != 0:
            return None, 'iptables -L %s rc %d: %s' % (chain, rc, first_line(out, 60))
        totals = parse_counters(out)
        if totals is None or target not in totals:
            return None, 'iptables -L %s -v -n -x showed no rule jumping to %s' % (chain, target)
        result[key] = totals[target]
    return result, ''


def take_snapshot(ctx):
    rules, why_rules = rules_fingerprint(ctx)
    counters, why_counters = read_counters(ctx)
    jumps, why_jumps = read_jump_counters(ctx)
    return {
        'epoch': int(time.time()), 'boot_id': read_boot_id(ctx), 'unit_since': unit_since(ctx),
        'rules_sha256': rules, 'rules_error': why_rules, 'counters': counters, 'counters_error': why_counters,
        'jumps': jumps, 'jumps_error': why_jumps,
    }


def compare_snapshots(before, now):
    """(ok, [problem], [note]): the gap was not rebuilt between the two snapshots."""
    problems, notes = [], []
    for key, label in (('boot_id', 'boot id'), ('unit_since', 'unit start time'), ('rules_sha256', 'rule text')):
        if not before.get(key):
            problems.append('%s unreadable at AG1' % label)
        elif not now.get(key):
            problems.append('%s unreadable now' % label)
        elif before[key] != now[key]:
            problems.append('%s changed since AG1 (%s -> %s): the gap was rebuilt or the host restarted' % (
                label, str(before[key])[:19], str(now[key])[:19]))
    b, n = before.get('counters'), now.get('counters')
    if not b or not n:
        problems.append('reject counters unreadable (%s)' % ((before.get('counters_error') if not b else now.get('counters_error')) or 'none'))
    else:
        for key in ('OUT', 'FWD'):
            if n[key]['REJECT'] < b[key]['REJECT']:
                problems.append('%s reject counter fell (%d -> %d): its chain was recreated' % (key, b[key]['REJECT'], n[key]['REJECT']))
        notes.append('rejected packets between AG1 and AG2: host +%d, containers +%d' % (
            n['OUT']['REJECT'] - b['OUT']['REJECT'], n['FWD']['REJECT'] - b['FWD']['REJECT']))
    jb, jn = before.get('jumps'), now.get('jumps')
    if not jb or not jn:
        problems.append('jump-rule counters unreadable (%s)' % ((before.get('jumps_error') if not jb else now.get('jumps_error')) or 'none'))
    else:
        for key, chain in (('OUT', 'OUTPUT'), ('FWD', 'DOCKER-USER')):
            if jn[key] < jb[key]:
                problems.append('the %s rules that jump to the reject chain counted fewer packets (%d -> %d): they were deleted and added again' % (
                    chain, jb[key], jn[key]))
    return not problems, problems, notes


# ───────────────────────────── air-gap checks ─────────────────────────────
def forward_jump_state(rules):
    """'ok' | 'missing' | 'late': FORWARD jumps to DOCKER-USER, and before DOCKER-FORWARD (Docker processes DOCKER-USER first)."""
    user = [i for i, rule in enumerate(rules) if rule == ['-A', 'FORWARD', '-j', 'DOCKER-USER']]
    docker = [i for i, rule in enumerate(rules) if rule == ['-A', 'FORWARD', '-j', 'DOCKER-FORWARD']]
    if not user:
        return 'missing'
    if docker and docker[0] < user[0]:
        return 'late'
    return 'ok'


def check_structure(ctx, v4):
    """([(name, ok, detail)], facts): the unit, the reject chains, the catch-all jumps, the resolvers.  facts say which
    side may be probed: a side whose jump or reject chain is missing is not."""
    checks = []
    rc_e, out_e = ctx.run(['systemctl', 'is-enabled', UNIT], timeout=15)
    rc_a, out_a = ctx.run(['systemctl', 'is-active', UNIT], timeout=15)
    enabled, active = rc_e == 0 and out_e.strip() == 'enabled', rc_a == 0 and out_a.strip() == 'active'
    checks.append(('unit', enabled and active, '%s is-enabled=%s (rc %d), is-active=%s (rc %d)' % (
        UNIT, first_line(out_e, 30) or '-', rc_e, first_line(out_a, 30) or '-', rc_a)))
    dumps = {}
    for chain in ('OUTPUT', 'FORWARD', 'DOCKER-USER', CHAIN_OUT, CHAIN_FWD):
        rc, out = iptables(ctx, '-S', chain)
        dumps[chain] = (rc, parse_rules(out) if rc == 0 else [], first_line(out, 60))
    unreadable = [c for c, (rc, _, why) in dumps.items() if rc != 0 and c not in ('DOCKER-USER', CHAIN_OUT, CHAIN_FWD)]
    if unreadable:
        checks.append(('iptables', False, 'iptables -S %s failed: %s' % (unreadable[0], dumps[unreadable[0]][2])))
    chain_ok = {}
    for chain in (CHAIN_OUT, CHAIN_FWD):
        rc, rules, why = dumps[chain]
        target = last_target(rules, chain) if rc == 0 else None
        chain_ok[chain] = target == 'REJECT'
        checks.append(('chain_' + chain.rsplit('-', 1)[1].lower(), target == 'REJECT',
                       '%s ends in %s' % (chain, target or ('missing: ' + (why or 'no rules')))))
    out_jump = has_catchall(dumps['OUTPUT'][1], 'OUTPUT', CHAIN_OUT)
    fwd_jump = has_catchall(dumps['DOCKER-USER'][1], 'DOCKER-USER', CHAIN_FWD)
    forward = forward_jump_state(dumps['FORWARD'][1])
    checks.append(('jump_output', out_jump, 'OUTPUT -j %s %s' % (CHAIN_OUT, 'present' if out_jump else 'MISSING')))
    checks.append(('jump_forward', fwd_jump and forward == 'ok', 'DOCKER-USER -j %s %s; FORWARD -j DOCKER-USER %s' % (
        CHAIN_FWD, 'present' if fwd_jump else 'MISSING', {'ok': 'present, before DOCKER-FORWARD', 'missing': 'MISSING',
                                                          'late': 'AFTER DOCKER-FORWARD (Docker processes DOCKER-USER first)'}[forward])))
    missing = []
    for ip in v4:
        for proto in ('udp', 'tcp'):
            if not covers(dumps['OUTPUT'][1], 'OUTPUT', CHAIN_OUT, ip, proto):
                missing.append('OUTPUT %s/%s' % (ip, proto))
            if not covers(dumps['DOCKER-USER'][1], 'DOCKER-USER', CHAIN_FWD, ip, proto):
                missing.append('DOCKER-USER %s/%s' % (ip, proto))
    checks.append(('resolvers', not missing, 'resolvers %s %s' % (
        ','.join(v4) or 'none (nothing to cover)', 'covered on 53 udp+tcp in OUTPUT and DOCKER-USER' if not missing
        else 'NOT covered: ' + ', '.join(missing[:4]))))
    return checks, {'out_jump': out_jump and chain_ok[CHAIN_OUT],
                    'fwd_jump': fwd_jump and forward == 'ok' and chain_ok[CHAIN_FWD]}


def ipv6_route(ctx):
    """'route' | 'none' | 'unknown': does this host have an IPv6 route to the probe address?  Without a route nothing is
    sent, so the IPv6 probe says something about the host, not about the gap."""
    rc, _ = ctx.run(['ip', '-6', 'route', 'get', HTTP6[0]], timeout=5)
    if rc == 0:
        return 'route'
    return 'unknown' if rc in (124, 125, 126, 127) else 'none'


def ip6_rule_state(ctx):
    """('present' | 'absent' | 'unknown', reason) for the air gap's ip6tables side: airgap.sh v2.4 and later reject the
    guest's own traffic to 2000::/3 (an OUTPUT jump to KRATE-AIRGAP-OUT6) whenever ip6tables exists, so the evidence must
    name whether that rule is there instead of asserting a version of the gap the code cannot see."""
    rc, out = ctx.run(['ip6tables', '-S', 'OUTPUT'], timeout=10, root=True)
    if rc != 0:
        return 'unknown', 'ip6tables %s' % ('not usable (rc %d)' % rc if rc in (124, 125, 126, 127) else 'rc %d: %s' % (rc, first_line(out, 40)))
    for line in out.splitlines():
        if line.startswith('-A OUTPUT') and '2000::/3' in line and 'KRATE-AIRGAP-OUT6' in line:
            return 'present', ''
    return 'absent', ''


def probe_host(ctx, facts):
    """Every probe is conclusive only through its own refusal or sentinel; the IPv6 row names the route fact and the
    installed v6 side of the gap (airgap.sh v2.4+: an ip6tables OUTPUT jump to KRATE-AIRGAP-OUT6 for 2000::/3) instead
    of attributing a refusal to the gap it cannot see."""
    results = {}
    if not facts['out_jump']:
        for name in ('host_http', 'host_dns', 'host_http6'):
            results[name] = ('cannot', 'not sent: OUTPUT has no catch-all jump to a reject chain that ends in REJECT, the request would leave the host')
        return results
    rc, out = ctx.run(['curl', '-q', '-sS', '-m', '5', '-o', '/dev/null', 'http://%s/' % HTTP4[0]], timeout=10, clean_env=True)
    results['host_http'] = classify_curl(rc)
    rc, out = ctx.run(['getent', 'hosts', PROBE_NAME], timeout=GETENT_SECONDS, clean_env=True)
    results['host_dns'] = classify_getent(rc, out)
    route = ipv6_route(ctx)
    v6, _v6_why = ip6_rule_state(ctx)
    v6_rule = {'present': 'the ip6tables rule rejects guest output to 2000::/3',
               'absent': 'no ip6tables rule for 2000::/3 was found',
               'unknown': 'ip6tables not usable'}[v6]
    if route == 'none':
        results['host_http6'] = ('blocked', 'no IPv6 route to the probe address on this host, nothing sent (the probe is not '
                                            'attempted; %s)' % v6_rule)
    else:
        rc, out = ctx.run(['curl', '-q', '-sS', '-6', '-m', '5', '-o', '/dev/null', 'http://[%s]/' % HTTP6[0]], timeout=10, clean_env=True)
        state, detail = classify_curl(rc)
        if route == 'route':
            bracket = (' [an IPv6 route exists and %s]' % v6_rule if v6 == 'present'
                       else ' [an IPv6 route exists; %s - the refusal is not attributed to the gap]' % v6_rule)
        else:
            bracket = ' [IPv6 route unknown: ip not usable; %s]' % v6_rule
        results['host_http6'] = (state, detail + bracket)
    return results


def docker_probe(ctx, image, script, network=None):
    argv = ['docker', 'run', '--rm', '--pull', 'never']
    if network:
        argv += ['--network', network]
    argv += ['--entrypoint', 'python3', image, '-c', script]
    rc, out = ctx.run(argv, timeout=CONTAINER_PROBE_SECONDS)
    return classify_sentinel(rc, out)


def journal_lookups(ctx, since, until=None):
    """(ok, lines or reason): dockerd's failed upstream lookups in the journal since/until (epoch seconds)."""
    argv = ['journalctl', '-u', 'docker', '--since', '@%d' % since]
    if until is not None:
        argv += ['--until', '@%d' % until]
    argv += ['--no-pager']
    rc, out = ctx.run(argv, timeout=90, root=True)
    if rc != 0:
        return False, 'journalctl rc %d: %s' % (rc, first_line(out, 80))
    if 'not seeing messages from other users' in out or 'Permission denied' in out or 'No journal files were found' in out:
        return False, 'the journal is not readable by this user (%s)' % first_line(out, 80)
    return True, [line for line in out.splitlines() if RESOLVER_ERROR in line]


def embedded_dns_probe(ctx, image):
    """Container DNS on a throw-away user-defined bridge: Docker's embedded resolver forwards the query from
    the host side (OUTPUT chain), which is the path the product's containers use.  Returns (state, detail,
    control) where control is the number of dockerd failed-lookup lines the probe itself produced (a blocked
    probe must produce at least one, or the journal count cannot see container lookups)."""
    token = hashlib.sha256(('%s%f' % (os.getpid(), time.time())).encode()).hexdigest()[:8]
    network = NET_PREFIX + token
    rc, out = ctx.run(['docker', 'network', 'create', '--label', NET_LABEL, network], timeout=40)
    if rc != 0:
        return 'cannot', 'could not create the probe network (docker rc %d): %s' % (rc, first_line(out, 70)), None
    started = int(time.time()) - 1
    try:
        state, detail = docker_probe(ctx, image, SCRIPT_DNS, network=network)
    finally:
        ctx.run(['docker', 'network', 'rm', network], timeout=40)
    if state != 'blocked':
        return state, detail, None
    seen, why = 0, ''
    for _ in range(10):
        ok, lines = journal_lookups(ctx, started)
        if not ok:
            why = lines
            break
        seen = len([line for line in lines if PROBE_NAME in line])
        if seen:
            break
        time.sleep(1)
    if why:
        return 'cannot', 'blocked, but the journal could not be read to confirm it: %s' % why, None
    if not seen:
        return 'cannot', 'blocked, but dockerd logged no failed lookup for the probe: the journal count would be blind', 0
    return 'blocked', '%s; dockerd logged %d failed lookup lines' % (detail, seen), seen


def sweep_probe_networks(ctx):
    rc, out = ctx.run(['docker', 'network', 'ls', '-q', '--filter', 'label=' + NET_LABEL], timeout=30)
    if rc == 0:
        for network in out.split():
            ctx.run(['docker', 'network', 'rm', network], timeout=30)


def stop_orphaned_watchers(ctx, _state_dir=None):
    """Stop supervisors whose run's marker file is gone (SF3): a `phase4_airgap.py watch-loop` whose --watcher-file no
    longer exists belongs to a run that ended (finish() deletes the run's state), so its supervisor is an orphan from a
    hard-killed or already-finished run.  A watcher whose state file still exists is someone's live subscription (an
    install-record `watch` step keeps its file until `end`) and is never touched.  Returns the number stopped."""
    rc, out = ctx.run(['ps', '-axww', '-o', 'pid=,command='], timeout=15)
    if rc != 0:
        return 0
    stopped = 0
    for line in out.splitlines():
        if 'phase4_airgap.py' not in line or 'watch-loop' not in line:
            continue
        fields = line.split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        pid, command = int(fields[0]), fields[1]
        marker = None
        pieces = command.split()
        for i, piece in enumerate(pieces):
            if piece == '--watcher-file' and i + 1 < len(pieces):
                marker = pieces[i + 1]
        if not marker or os.path.exists(marker):
            # a live subscription keeps its marker (an install-record `watch` step keeps the file until `end`);
            # a markerless supervisor belongs to a run that ended
            continue
        log('stopping the orphaned watcher %d (%s: its marker file %s is gone)' % (pid, first_line(command, 80), marker))
        kill_watcher({'pid': pid})
        stopped += 1
    return stopped


def run_checks(ctx, image, containers=True):
    """All air-gap checks of one point in time.  Returns {'ok', 'checks', 'probes', 'facts', 'evidence', 'control'}."""
    v4, v6 = resolvers_from(ctx.args.resolv_conf)
    checks, facts = check_structure(ctx, v4)
    probes = probe_host(ctx, facts)
    control = None
    if containers:
        if image is None:
            for name in ('container_http', 'container_dns', 'container_dns_embedded'):
                probes[name] = ('cannot', 'no probe image')
        elif not facts['fwd_jump']:
            for name in ('container_http', 'container_dns', 'container_dns_embedded'):
                probes[name] = ('cannot', 'not sent: DOCKER-USER/FORWARD have no catch-all reject rule, the request would leave the host')
        else:
            probes['container_http'] = docker_probe(ctx, image, SCRIPT_HTTP)
            probes['container_dns'] = docker_probe(ctx, image, SCRIPT_DNS)
            if facts['out_jump']:
                state, detail, control = embedded_dns_probe(ctx, image)
                probes['container_dns_embedded'] = (state, detail)
            else:  # Docker's embedded resolver forwards from the host side: through OUTPUT
                probes['container_dns_embedded'] = ('cannot', "not sent: OUTPUT has no reject rule and Docker's embedded resolver "
                                                              'forwards the lookup from the host side')
    ok = all(c[1] for c in checks) and all(p[0] == 'blocked' for p in probes.values())
    bad = ['%s: %s' % (name, detail) for name, good, detail in checks if not good]
    bad += ['%s %s: %s' % (name, 'REACHED THE NETWORK' if state == 'leak' else 'not proven blocked', detail)
            for name, (state, detail) in probes.items() if state != 'blocked']
    parts = []
    if bad:
        parts.append('FAILED: ' + ' | '.join(bad))
    parts.append('; '.join('%s %s' % (n, 'ok' if g else 'FAIL') for n, g, _ in checks) + ' (' + '; '.join(
        d for n, g, d in checks if g and n in ('unit', 'resolvers')) + ')')
    parts.append('probes ' + '; '.join('%s=%s: %s' % (n, probes[n][0], probes[n][1]) for n in PROBE_ORDER if n in probes))
    if v6:
        parts.append('IPv6 resolvers listed (their coverage is not checked by this row; the gap rejects guest output to '
                     '2000::/3 when ip6tables exists, per airgap.sh v2.4): %s' % ','.join(v6))
    return {'ok': ok, 'checks': checks, 'probes': probes, 'facts': facts, 'evidence': '. '.join(parts), 'control': control}


# ───────────────────────────── the pull watcher (AG3) ─────────────────────────────
def watcher_alive(ctx, pid):
    """The pid exists and is still the watcher's supervisor (`phase4_airgap.py watch-loop`), not a recycled pid.  A zombie has
    an empty command line on Linux and `ps` prints it without arguments, so it never matches."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError:
        return False
    cmdline = read_text('/proc/%d/cmdline' % pid)
    if cmdline is not None:
        command = cmdline.replace('\0', ' ')
    else:
        rc, command = ctx.run(['ps', '-p', str(pid), '-o', 'command='], timeout=10)
        if rc != 0:
            return False
    return 'phase4_airgap' in command and 'watch-loop' in command and 'defunct' not in command


def kill_watcher(watcher):
    """Stop the supervisor and its docker events child (the supervisor leads its own session)."""
    try:
        pid = int(watcher['pid'])
    except (KeyError, TypeError, ValueError):
        return
    for kill in (lambda: os.killpg(pid, signal.SIGTERM), lambda: os.kill(pid, signal.SIGTERM)):
        try:
            kill()
            return
        except OSError:
            continue


def control_event(_ctx, events_file, action, name, wait=15):
    """True when the watcher's file shows the volume event for `name`."""
    deadline = time.time() + wait
    while True:
        events, _ = parse_events(read_text(events_file))
        if any(t == 'volume' and a == action and i == name for t, a, i, _ in events):
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.2)


def control_cycle(ctx, events_file, token):
    """Create and remove a throw-away volume; True when the create event reached the subscription."""
    name = CONTROL_PREFIX + token
    rc, _ = ctx.run(['docker', 'volume', 'create', name], timeout=40)
    if rc != 0:
        return False
    created = control_event(ctx, events_file, 'create', name)
    ctx.run(['docker', 'volume', 'rm', name], timeout=40)
    return created


def count_ring(since):
    """Number of events of ANY type the daemon replays from `since` on; None when the daemon cannot be reached.  `--until` two
    seconds ahead makes the CLI return at that timer (moby getEvents) and includes the current second, which a restart fills with
    the burst of the restarting containers; a count at the ring's limit means older events may have been dropped."""
    until = int(time.time()) + 2
    try:
        proc = subprocess.run(['docker', 'events', '--since', str(since), '--until', str(until), '--format', '{{.TimeNano}}'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return len([line for line in proc.stdout.decode('utf-8', 'replace').splitlines() if line.strip()])


def watch_loop(args):
    """The supervisor of AG3 (started by start_watcher, a session of its own): keeps one `docker events --since <window start>`
    subscription attached and writes it to the events file.  When the stream ends (the CLI returns at EOF: the daemon was
    restarted, or the CLI itself died) it writes a detach marker, waits for the daemon, counts the events of any type the
    daemon's ring holds since the window start, writes an attach marker with that count and subscribes again with the same
    --since: the daemon's ring is replayed, so a pull between the stream end and the re-attach is read.  Every stream end
    writes its detach marker (a missing marker must fail the row, SF2).  Stops at --until, on SIGTERM, or when its state
    file (--watcher-file) disappears: finish() deletes the run's state on every path that reaches it, so a supervisor whose
    owner is gone stops itself instead of idling to the 2 h backstop (SF3)."""
    import threading

    child_holder = []  # the running `docker events` child, if any (a list: it must be assignable from the signal handler)
    state_gone = threading.Event()

    def stop_child():
        for proc in child_holder:
            try:
                proc.terminate()  # unblocks the stream read so the main loop can exit
            except OSError:
                pass

    def stop(_signum, _frame):
        stop_child()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)

    def watch_state_file():
        """The state file is the run's marker: gone means the owner stopped (finish() deletes the state).  It terminates the
        child as well, or the main loop would stay blocked in the stream read and never reach the state_gone check."""
        while not state_gone.is_set():
            if not os.path.exists(args.watcher_file):
                state_gone.set()
                stop_child()
                return
            time.sleep(WATCH_TICK)

    if args.watcher_file:
        threading.Thread(target=watch_state_file, daemon=True).start()
    signal.signal(signal.SIGINT, stop)
    since, until = int(args.since), int(args.until)
    with open(args.events_file, 'ab', buffering=0) as events, open(args.err_file, 'ab') as err:
        def mark(action, **extra):
            doc = {'Type': 'airgap', 'Action': action, 'time': int(time.time())}
            doc.update(extra)
            events.write((json.dumps(doc) + '\n').encode('utf-8'))
        attempts = 0
        while time.time() < until:
            if state_gone.is_set():
                break
            ring = count_ring(since)
            if ring is None:  # the daemon is not reachable (down, restarting): try again
                time.sleep(1)
                continue
            attempts += 1
            mark('attach', n=attempts, ring=ring, ring_full=ring >= RING_LIMIT)
            argv = ['docker', 'events', '--filter', 'type=image', '--filter', 'type=volume', '--format', '{{json .}}',
                    '--since', str(since), '--until', str(until)]
            try:
                child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL)
            except OSError:
                time.sleep(1)
                continue
            child_holder.append(child)
            stream = child.stdout
            if stream is None:  # not reachable with stdout=PIPE; keeps the static analysis honest
                child.wait()
                child_holder.clear()
                continue
            for raw in stream:
                events.write(raw)
            rc = child.wait()
            child_holder.clear()
            mark('detach', n=attempts, rc=rc)
            time.sleep(1)
    if state_gone.is_set():
        stop_child()
    return 0


def start_watcher(ctx, state_dir, prefix):
    """Start the supervisor and prove the subscription is attached (control event).  Returns the state dict (always; 'error'
    says what failed).  The pid is written to <prefix>watcher.json at once, so a step that is killed leaves a way to stop it."""
    events_file = os.path.join(state_dir, prefix + 'events.jsonl')
    err_file = os.path.join(state_dir, prefix + 'events.err')
    started = int(time.time())
    watcher = {'events_file': events_file, 'err_file': err_file, 'started_epoch': started, 'started_utc': utc(started),
               'pid': None, 'control_start': False, 'error': '', 'docker_since': unit_since(ctx, 'docker.service'),
               'state_file': os.path.join(state_dir, prefix + 'watcher.json')}
    for path in (events_file, err_file):
        open(path, 'wb').close()
    argv = [sys.executable, '-I', '-B', os.path.abspath(__file__), 'watch-loop', '--events-file', events_file,
            '--err-file', err_file, '--since', str(started), '--until', str(started + WATCH_SECONDS),
            '--watcher-file', watcher['state_file']]  # the state file is the run's marker: deleting it stops the supervisor
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                start_new_session=True)
    except OSError as exc:
        watcher['error'] = 'could not start the watcher: %s' % exc
        return watcher
    watcher['pid'] = proc.pid
    try:
        write_json_atomic(watcher['state_file'], watcher)
    except BaseException:  # a SIGTERM here would leave a supervisor nobody knows the pid of
        kill_watcher(watcher)
        raise
    token = '%s%d' % (hashlib.sha256(('%d%f' % (proc.pid, time.time())).encode()).hexdigest()[:6], started % 1000)
    watcher['token_start'] = token
    created = control_cycle(ctx, events_file, 's' + token)
    watcher['control_start'] = created
    if not created:
        watcher['error'] = 'the control volume event never reached the subscription (%s)' % (
            first_line(read_text(err_file) or '', 80) or 'docker events printed nothing')
        kill_watcher(watcher)  # AG3 is FAIL already; a supervisor that never attached must not loop to its 2 h backstop
    write_json_atomic(watcher['state_file'], watcher)
    return watcher


def stop_watcher(ctx, watcher):
    """End control, stop, and read the stream.  Returns a dict: alive, control_start, control_end, events, pulls, bad,
    attaches, detaches, docker_since_end, error."""
    result = {'alive': False, 'control_start': False, 'control_end': False, 'events': 0, 'pulls': [], 'bad': 0, 'error': '',
              'attaches': [], 'detaches': [], 'docker_since_end': unit_since(ctx, 'docker.service')}
    pid = watcher.get('pid')
    events_file = watcher.get('events_file') or ''
    result['alive'] = watcher_alive(ctx, pid)
    if not result['alive']:
        result['error'] = 'the docker events subscription is not running any more (%s)' % (
            first_line(read_text(watcher.get('err_file') or '') or '', 80) or 'it ended without a message')
    else:
        result['control_end'] = control_cycle(ctx, events_file, 'e' + str(watcher.get('token_start', '')))
    if pid and result['alive']:
        kill_watcher(watcher)
        for _ in range(50):
            if not watcher_alive(ctx, pid):
                break
            time.sleep(0.1)
        else:
            try:
                os.killpg(int(pid), signal.SIGKILL)
            except OSError:
                pass
    events, markers, bad = parse_stream(read_text(events_file))
    result['events'], result['bad'] = len(events), bad
    result['pulls'] = [i or n for t, a, i, n in events if t == 'image' and a == 'pull']
    result['attaches'] = [m for m in markers if m.get('Action') == 'attach']
    result['detaches'] = [m for m in markers if m.get('Action') == 'detach']
    start_token = watcher.get('token_start')
    result['control_start'] = bool(start_token) and any(
        t == 'volume' and a == 'create' and i == CONTROL_PREFIX + 's' + start_token for t, a, i, _ in events)
    return result


def watcher_segments(stopped, restarted):
    """([problem], text): what the attach and detach markers say.  A re-attach is labelled as a bridged daemon restart only
    when docker.service actually restarted (the fact comes from the ActiveEnterTimestamp comparison in watcher_verdict);
    a re-attach without its detach marker is a problem, never a gap computed from a zero epoch; a ring at its limit at an
    attach cannot prove 0 pulls for that segment, and the '< limit' is printed only when it is true."""
    problems, parts = [], []
    attaches, detaches = stopped['attaches'], stopped['detaches']
    if not attaches:
        return ['the subscription wrote no attach marker'], 'no attach marker'
    for index, attach in enumerate(attaches):
        ring = attach.get('ring')
        if attach.get('ring_full') or (isinstance(ring, int) and ring >= RING_LIMIT):
            problems.append("the daemon's event ring held %s events (its limit) when the subscription attached at %s: a pull before the "
                            'attach cannot be excluded' % (ring, utc(attach.get('time'))))
        if index == 0:
            parts.append('attached %s (ring %s events)' % (utc(attach.get('time')), ring))
            continue
        label = 'daemon restart bridged: ' if restarted else 're-attached after the stream ended (docker.service was not restarted): '
        ended = detaches[index - 1] if index - 1 < len(detaches) else None
        if not isinstance(ended, dict):
            problems.append('the stream that ended before the re-attach at %s left no detach marker: what it saw cannot be '
                            'accounted' % utc(attach.get('time')))
            parts.append('%sstream ended (no detach marker), re-attached %s, ring replayed from the window start' % (
                label, utc(attach.get('time'))))
            continue
        if not isinstance(ring, int) or not 0 <= ring < RING_LIMIT:
            ring_part = ', replayed ring: %s events' % ring
        else:
            ring_part = ' with the daemon\'s ring replayed from the window start (%s events < %d)' % (ring, RING_LIMIT)
        parts.append('%sstream ended %s (rc %s), re-attached %s after %d s%s' % (
            label, utc(ended.get('time')), ended.get('rc'), utc(attach.get('time')),
            max(0, int(attach.get('time', 0)) - int(ended.get('time', 0))), ring_part))
    return problems, '; '.join(parts)


def watcher_verdict(watcher, stopped, window_end):
    """(ok, evidence) of AG3."""
    problems = []
    if watcher.get('error'):
        problems.append(watcher['error'])
    if not stopped['alive']:
        problems.append(stopped['error'])
    if not stopped['control_start']:
        problems.append('the control event at the start was not seen')
    if not stopped['control_end']:
        problems.append('the control event at the end was not seen')
    if stopped['bad']:
        problems.append('%d unreadable event lines' % stopped['bad'])
    if stopped['pulls']:
        problems.append('IMAGE PULLED: %s' % ', '.join(str(p) for p in stopped['pulls'][:5]))
    since_start, since_end = watcher.get('docker_since'), stopped.get('docker_since_end')
    restarted = bool(since_start and since_end and since_start != since_end)
    if restarted and len(stopped['attaches']) < 2:
        problems.append('docker.service was restarted (%s -> %s) but the subscription did not re-attach' % (since_start, since_end))
    seg_problems, segments = watcher_segments(stopped, restarted)
    problems += seg_problems
    window = '%s..%s (%d s)' % (watcher.get('started_utc'), utc(window_end), window_end - int(watcher.get('started_epoch') or window_end))
    facts = ("docker events subscription (type=image, type=volume) opened with --since the window start, so it reads only events "
             "from the window on (the daemon's ring holds its last %d events and is replayed from that second); pid %s over %s; %s; "
             "docker.service %s; control events seen at start=%s, end=%s; %d events, %d pulls; a failed pull is not an event and is "
             "not counted by AG5 either (AG5 counts container lookups and forwarded packets)" % (
                 RING_LIMIT, watcher.get('pid'), window, segments,
                 'restarted in the window (%s -> %s)' % (since_start, since_end) if restarted else 'not restarted in the window',
                 stopped['control_start'], stopped['control_end'], stopped['events'], len(stopped['pulls'])))
    return not problems, ('FAILED: ' + ' | '.join(problems) + '. ' + facts) if problems else facts


# ───────────────────────────── AG5 ─────────────────────────────
def lookups_verdict(ctx, window_start, window_end, before, now, controls, exit_path):
    """(ok, evidence) of AG5."""
    problems, facts = [], []
    b, n = before.get('counters'), now.get('counters')
    if not b or not n:
        problems.append('reject counters unreadable (%s)' % ((before.get('counters_error') if not b else now.get('counters_error')) or 'no counters'))
    else:
        delta = n['FWD']['REJECT'] - b['FWD']['REJECT']
        facts.append('%s rejected +%d packets' % (CHAIN_FWD, delta))
        if delta < 0:
            problems.append('%s counter fell (%d -> %d)' % (CHAIN_FWD, b['FWD']['REJECT'], n['FWD']['REJECT']))
        elif delta > 0:
            problems.append('containers sent %d packets to the outside (rejected by %s)%s' % (delta, CHAIN_FWD, fwd_sources(ctx, window_start, window_end)))
    ok, lines = journal_lookups(ctx, window_start, window_end) if window_end > window_start else (True, [])
    if not ok:
        problems.append('dockerd lookups unknown: %s' % lines)
    else:
        public, single = split_lookups(lookup_names(lines), search_domains_from(ctx.args.resolv_conf))
        facts.append("dockerd 'failed to query external DNS server' lines: %d (public-looking names: %s; single-label service names: %s)" % (
            len(lines), counted(public), counted(single)))
        if public:
            problems.append('containers asked for public-looking names: %s' % counted(public))
    for label, value in controls:
        if not value:
            problems.append('journal control missing at %s: the embedded-DNS probe left no dockerd lookup line, so the count is blind' % label)
    facts.append('journal control: embedded-DNS probe lookups visible at AG1=%s, AG2=%s' % tuple(
        v if v else 'none' for _, v in controls))
    facts.append('window %s..%s (%d s)%s' % (utc(window_start), utc(window_end), window_end - window_start,
                                            ', ended by the exit path: teardown is inside it' if exit_path else ', first row to last row (teardown excluded)'))
    text = '. '.join(facts)
    return not problems, ('FAILED: ' + ' | '.join(problems) + '. ' + text) if problems else text


def fwd_sources(ctx, since, until):
    rc, out = ctx.run(['journalctl', '-k', '--since', '@%d' % since, '--until', '@%d' % until, '--no-pager'], timeout=60, root=True)
    if rc != 0:
        return ''
    groups = {}
    for line in out.splitlines():
        if 'krate-airgap-fwd:' not in line:
            continue
        fields = dict(re.findall(r'\b(SRC|DST|PROTO|DPT)=(\S+)', line))
        key = '%s>%s:%s/%s' % (fields.get('SRC', '?'), fields.get('DST', '?'), fields.get('DPT', '?'), fields.get('PROTO', '?'))
        groups[key] = groups.get(key, 0) + 1
    return ' [kernel log: %s]' % counted(groups, 3) if groups else ' [no kernel log line in the window; the log is rate-limited]'


# ───────────────────────────── the install record (AG4) ─────────────────────────────
def verify_record(ctx):
    """(ok, evidence) of AG4.  A key that is missing is never read as "0 pulls": every field must be present with its type."""
    args = ctx.args
    text = read_text(args.record)
    if text is None:
        return False, ('no install record at %s: the offline install of this host was not proven (provision with '
                       '`phase4_airgap.py install-record begin|watch|end`); on a bundle host that is a FAIL, not a skip' % args.record)
    try:
        record = json.loads(text)
        begin, watch, end = record['begin'], record['watch'], record['end']
        for part in (begin, watch, end):
            if not isinstance(part, dict):
                raise TypeError('a record section is not an object')
    except (ValueError, KeyError, TypeError) as exc:
        return False, 'the install record at %s is not complete or not readable (%s: %s)' % (args.record, type(exc).__name__, str(exc)[:60])
    problems = []
    if record.get('format') != RECORD_FORMAT or record.get('status') != 'complete':
        problems.append('record format %r status %r (want %d, complete)' % (record.get('format'), record.get('status'), RECORD_FORMAT))
    if begin.get('ok') is not True:
        problems.append('the air gap was not proven up before the first product step: %s' % str(begin.get('why', 'no result'))[:120])
    if watch.get('control_start') is not True:
        problems.append('the install pull watcher never proved it was attached')
    if end.get('ok') is not True:
        problems.append('the air gap was not proven up after the install: %s' % str(end.get('why', 'no result'))[:120])
    if end.get('watch_ok') is not True:
        problems.append('the install pull watcher is not proven: %s' % str(end.get('watch_evidence', 'no result'))[:200])
    pulls = end.get('pulls')
    if not isinstance(pulls, list):
        problems.append("the record has no 'pulls' list (a missing key is not '0 pulls')")
    elif pulls:
        problems.append('IMAGES WERE PULLED during the install: %s' % ', '.join(str(p) for p in pulls[:5]))
    lookups = end.get('lookups_public')
    if not isinstance(lookups, str):
        problems.append("the record has no 'lookups_public' text (a missing key is not 'no lookups')")
    elif lookups:
        problems.append('containers asked for public-looking names during the install: %s' % lookups)
    if end.get('journal_ok') is not True:
        problems.append('the install lookup window could not be read from the journal')
    events = end.get('events')
    if isinstance(events, bool) or not isinstance(events, int) or events < 2:
        problems.append("the record's watcher saw %r events: both control events make at least 2" % (events,))
    script_now = sha256_file(args.script)
    if script_now is None or script_now != begin.get('script_sha256'):
        problems.append('the air-gap script now installed (%s) is not the one that covered the install (%s)' % (
            (script_now or 'unreadable')[:12], str(begin.get('script_sha256'))[:12]))
    recorded = end.get('product_sha256')
    product_now = product_digests(args.edition_dir)
    if not isinstance(recorded, dict) or not recorded:
        problems.append('the record carries no digests of the installed product, so it cannot be tied to this bundle')
    else:
        differ = sorted(name for name in set(recorded) | set(product_now) if recorded.get(name) != product_now.get(name))
        if differ:
            problems.append('the installed product is not the one installed under this record (differs: %s)' % ', '.join(differ))
    boot_now = read_boot_id(ctx)
    facts = ('record %s written %s; install window %s..%s; air gap proven before docker-install and after the install; '
             'watcher %s; %d pulls, public-name lookups by containers: %s; same air-gap script (sha256 %s) and same product '
             '(digests of %s); %s' % (
                 args.record, end.get('utc'), watch.get('started_utc'), end.get('utc'), str(end.get('watch_summary', '?'))[:120],
                 len(pulls) if isinstance(pulls, list) else -1, lookups or 'none', str(begin.get('script_sha256'))[:12],
                 ', '.join(sorted(product_now)), 'same boot as the install' if boot_now and boot_now == end.get('boot_id')
                 else 'the host restarted after the install'))
    return not problems, ('FAILED: ' + ' | '.join(problems) + '. ' + facts) if problems else facts


def write_json_atomic(path, doc):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write('\n')
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def load_json(path):
    text = read_text(path)
    if text is None:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def cmd_install_record(ctx, step):
    args = ctx.args
    state = args.state or DEFAULT_RECORD_STATE
    os.makedirs(state, exist_ok=True)
    record = load_json(args.record) or {'format': RECORD_FORMAT}
    if step == 'begin':
        v4, _ = resolvers_from(args.resolv_conf)
        checks, facts = check_structure(ctx, v4)
        probes = probe_host(ctx, facts)
        ok = all(c[1] for c in checks) and all(p[0] == 'blocked' for p in probes.values())
        why = '; '.join(['%s: %s' % (n, d) for n, g, d in checks if not g] + ['%s: %s' % (n, p[1]) for n, p in probes.items() if p[0] != 'blocked'])
        record = {'format': RECORD_FORMAT, 'status': 'begun', 'begin': {
            'ok': ok, 'why': why, 'utc': utc(), 'epoch': int(time.time()), 'boot_id': read_boot_id(ctx),
            'script_sha256': sha256_file(args.script), 'unit_since': unit_since(ctx),
            'probes': {n: '%s: %s' % p for n, p in probes.items()}}}
        write_json_atomic(args.record, record)
        log('begin: %s' % ('the air gap is up before the first product step' if ok else 'NOT UP: ' + why))
        return 0 if ok else 1
    if step == 'watch':
        if record.get('status') != 'begun':
            log('watch: no begun record at %s (run `install-record begin` first)' % args.record)
            return 1
        watcher = start_watcher(ctx, state, 'install-')
        record['watch'] = {k: watcher.get(k) for k in ('pid', 'started_epoch', 'started_utc', 'events_file', 'err_file',
                                                        'token_start', 'control_start', 'error', 'docker_since', 'state_file')}
        record['status'] = 'watching'
        write_json_atomic(args.record, record)
        log('watch: %s' % ('subscription attached (control event seen)' if watcher['control_start'] else 'FAILED: ' + watcher['error']))
        return 0 if watcher['control_start'] else 1
    if step == 'end':
        if record.get('status') != 'watching':
            log('end: no watching record at %s' % args.record)
            return 1
        if not args.edition_dir or not args.mon_dir:
            log('end: --edition-dir and --mon-dir are required (the bundle whose install this record covers)')
            return 2
        image, _ = pick_image(ctx)
        watch = record['watch']
        end_epoch = int(time.time())  # the window ends before this step's own probes, whose lookups are not the install's
        journal_ok, lines = journal_lookups(ctx, int(watch['started_epoch']), end_epoch) if end_epoch > int(watch['started_epoch']) else (True, [])
        public, single = split_lookups(lookup_names(lines), search_domains_from(args.resolv_conf)) if journal_ok else ({}, {})
        result = run_checks(ctx, image)
        stopped = stop_watcher(ctx, watch)
        watch_ok, watch_evidence = watcher_verdict(watch, stopped, end_epoch)
        counters, _ = read_counters(ctx)
        record['end'] = {
            'ok': result['ok'], 'why': result['evidence'][:300], 'utc': utc(end_epoch), 'epoch': end_epoch,
            'boot_id': read_boot_id(ctx), 'unit_since': unit_since(ctx), 'product_sha256': product_digests(args.edition_dir),
            'image': image, 'watcher_alive': stopped['alive'], 'control_end': stopped['control_end'], 'pulls': stopped['pulls'],
            'watch_ok': watch_ok, 'watch_evidence': watch_evidence[:600], 'attaches': len(stopped['attaches']),
            'watch_summary': '%d attach(es), controls seen at start and end, %d events, %d pulls' % (
                len(stopped['attaches']), stopped['events'], len(stopped['pulls'])) if watch_ok else 'not proven',
            'events': stopped['events'], 'journal_ok': journal_ok, 'lookups_public': counted(public) if public else '',
            'lookups_single_label': counted(single) if single else '', 'counters': counters}
        record['watch']['control_start'] = bool(record['watch'].get('control_start')) and stopped['control_start']
        record['status'] = 'complete'
        write_json_atomic(args.record, record)
        ok, evidence = verify_record(ctx)
        log('end: %s' % evidence)
        return 0 if ok else 1
    return 2


# ───────────────────────────── before / after ─────────────────────────────
EMITTED = []


def emit(rows, row_id, result, evidence):
    evidence = evidence.replace('\t', ' ').replace('\n', ' | ')
    rows.append((row_id, result, evidence))
    EMITTED.append(row_id)
    print('%s\t%s\t%s' % (row_id, result, evidence))
    sys.stdout.flush()


def not_run_rows(kind, ids, rows):
    reasons = {
        'darwin': 'not run on the Mac: the air gap is a property of the VM provisioning, and the Mac is the connected build host whose Docker '
                  'runs in a VM this gate cannot inspect; the VM receipt carries these rows',
        'checkout': 'not run: the edition directory is a git checkout, not an installed bundle (a development or CI host); the air gap is '
                    'proven only on a bundle host',
    }
    for row_id in ids:
        emit(rows, row_id, 'NOT_RUN', reasons.get(kind, 'not run: host kind %s' % kind))


def cmd_before(ctx):
    args = ctx.args
    rows = []
    if args.host_kind != 'bundle':
        not_run_rows(args.host_kind, ROWS_BEFORE, rows)
        return 0
    state_dir = args.state
    os.makedirs(state_dir, exist_ok=True)
    os.chmod(state_dir, 0o700)
    orphans = stop_orphaned_watchers(ctx, state_dir)
    if orphans:
        log('stopped %d orphaned watcher(s) from earlier runs' % orphans)
    started = int(time.time())
    image, image_note = pick_image(ctx)
    log('probe image: %s' % image_note)
    sweep_probe_networks(ctx)
    # The window opens here, before the first probe and before the first row.
    watcher = None
    try:
        watcher = start_watcher(ctx, state_dir, '')
        log('pull watcher: %s' % ('attached, control event seen' if watcher['control_start'] else 'FAILED: ' + watcher['error']))
        result = run_checks(ctx, image)
        snapshot = take_snapshot(ctx)
        window_start = int(math.ceil(time.time())) + 1  # the probes' own lookups end before this second
        emit(rows, 'AG1', 'PASS' if result['ok'] else 'FAIL',
             '%s. snapshot: boot %s, unit since %s, rules sha256 %s, probe image %s' % (
                 result['evidence'], (snapshot['boot_id'] or '?')[:8], snapshot['unit_since'] or '?',
                 (snapshot['rules_sha256'] or '?')[:12], image or 'none'))
        state = {'format': 1, 'started_epoch': started, 'started_utc': utc(started), 'window_start': window_start, 'snapshot': snapshot,
                 'ag1_ok': result['ok'], 'ag1_control': result['control'], 'image': image, 'watcher': watcher}
        write_json_atomic(os.path.join(state_dir, 'before.json'), state)
        ok, evidence = verify_record(ctx)
        emit(rows, 'AG4', 'PASS' if ok else 'FAIL', evidence)
        return 0 if all(r[1] != 'FAIL' for r in rows) else 1
    except BaseException:  # a crash or a SIGTERM before the state file exists must not leave the subscription running
        kill_watcher(watcher or load_json(os.path.join(state_dir, 'watcher.json')) or {})  # start_watcher writes the file at once
        raise


def cmd_after(ctx):
    args = ctx.args
    rows = []
    if args.host_kind != 'bundle':
        not_run_rows(args.host_kind, ROWS_AFTER, rows)
        return 0
    state = load_json(os.path.join(args.state, 'before.json'))
    if not state:
        orphan = load_json(os.path.join(args.state, 'watcher.json'))
        stopped_note = ''
        if orphan and orphan.get('pid'):
            kill_watcher(orphan)  # the before step ended before it wrote its state: its subscription is stopped here
            stopped_note = '; the subscription it had started was stopped'
        for row_id in ROWS_AFTER:
            emit(rows, row_id, 'FAIL', 'no state from the before step (%s): the air gap was not proven before the first row, so nothing '
                                      'can be proven about the window%s' % (os.path.join(args.state, 'before.json'), stopped_note))
        return 1
    stopped = None
    try:
        window_end = int(time.time())  # the first thing: probes and the end control stay outside the lookup window
        now = take_snapshot(ctx)
        image = state.get('image')
        result = run_checks(ctx, image)
        same, problems, notes = compare_snapshots(state['snapshot'], now)
        ag2_ok = result['ok'] and same
        evidence2 = result['evidence']
        if problems:
            evidence2 = 'FAILED: ' + ' | '.join(problems) + '. ' + evidence2
        evidence2 += '. unchanged since AG1: boot %s, unit since %s, rules sha256 %s; %s' % (
            (now['boot_id'] or '?')[:8], now['unit_since'] or '?', (now['rules_sha256'] or '?')[:12], '; '.join(notes) or 'counters unreadable')
        emit(rows, 'AG2', 'PASS' if ag2_ok else 'FAIL', evidence2)
        stopped = stop_watcher(ctx, state['watcher'])
        ok3, evidence3 = watcher_verdict(state['watcher'], stopped, int(time.time()))
        emit(rows, 'AG3', 'PASS' if ok3 else 'FAIL', evidence3)
        ok5, evidence5 = lookups_verdict(ctx, state['window_start'], window_end, state['snapshot'], now,
                                         (('AG1', state.get('ag1_control')), ('AG2', result['control'])), args.exit_path)
        emit(rows, 'AG5', 'PASS' if ok5 else 'FAIL', evidence5)
    finally:
        if stopped is None:  # a crash must not leave the subscription running until its 24 h backstop
            for ref in (state.get('watcher'), load_json(os.path.join(args.state, 'watcher.json'))):
                if isinstance(ref, dict):
                    kill_watcher(ref)
    return 0 if all(r[1] != 'FAIL' for r in rows) else 1


def build_parser():
    parser = argparse.ArgumentParser(description='Air-gap rows AG1-AG5 of the identity gate')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('before', 'after'):
        p = sub.add_parser(name)
        p.add_argument('--host-kind', required=True, choices=('bundle', 'checkout', 'darwin'))
        p.add_argument('--state', required=True)
        p.add_argument('--edition-dir', required=True)
        p.add_argument('--mon-dir', required=True)
        p.add_argument('--exit-path', action='store_true', help='called from the runner exit path: teardown is inside the window')
    rec = sub.add_parser('install-record')
    rec.add_argument('step', choices=('begin', 'watch', 'end'))
    rec.add_argument('--state', default='')
    rec.add_argument('--edition-dir', default='')
    rec.add_argument('--mon-dir', default='')
    loop = sub.add_parser('watch-loop', help='the AG3 subscription supervisor (started by the steps above)')
    loop.add_argument('--events-file', required=True)
    loop.add_argument('--err-file', required=True)
    loop.add_argument('--since', required=True, type=int)
    loop.add_argument('--until', required=True, type=int)
    loop.add_argument('--watcher-file', required=True)  # the run's marker: its deletion stops the supervisor
    for p in sub.choices.values():
        p.add_argument('--record', default=DEFAULT_RECORD)
        p.add_argument('--script', default=DEFAULT_SCRIPT)
        p.add_argument('--boot-id-file', default=DEFAULT_BOOT_ID)
        p.add_argument('--resolv-conf', action='append', default=None)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == 'watch-loop':
        return watch_loop(args)
    if not args.resolv_conf:
        args.resolv_conf = list(DEFAULT_RESOLV)
    ctx = Ctx(args)
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))  # let the cleanup of a terminated step run
    try:
        if args.command == 'install-record':
            return cmd_install_record(ctx, args.step)
        return cmd_before(ctx) if args.command == 'before' else cmd_after(ctx)
    except Exception as exc:  # the rows of this step must exist: a crash is a FAIL row, never a missing one
        ids = ROWS_BEFORE if args.command == 'before' else ROWS_AFTER if args.command == 'after' else ()
        for row_id in ids:
            if row_id in EMITTED:
                continue
            print('%s\tFAIL\thelper error %s: %s' % (row_id, type(exc).__name__, str(exc)[:200].replace('\n', ' ')))
        sys.stdout.flush()
        log('helper error %s: %s' % (type(exc).__name__, exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())