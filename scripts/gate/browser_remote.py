#!/usr/bin/env python3
"""Guest-side requester for the Mac agent rendezvous (TOPOFIX-REVIEW F4).

The guest runner (scripts/gate-identity.sh) asks the Mac agent for one planned row at a
time. The request is EXACTLY ``{"schema": 1, "id": ..., "row": ..., "nonce": ...}`` — no
paths, no secrets, no arguments: the agent owns its row table (request carries nothing the
agent does not already know). Responses are the agent's ``resp-<id>.json``; the nonce binds
every hello and response to this run.

CLI (python3 -I, Python 3.9+):

  python3 -I browser_remote.py hello  --rendezvous DIR [--max-age S] [--nonce TOKEN]
  python3 -I browser_remote.py request --rendezvous DIR --nonce TOKEN --row ID [--timeout S]

Exit codes: 0 the response's own exit was 0; 1 bad usage; 2 the response says the agent
refused/failed (its exit is printed on stdout before exiting 2); 3 response timeout; 4 the
agent hello is stale (never observed, or older than --max-age); 5 nonce mismatch or schema
mismatch; 6 the response is not the expected shape.
Nothing secret is printed: the response's stdout_tail is already agent-redacted.
"""
import json
import os
import re
import sys
import time


def _atomic_write(path, text):
    tmp = os.path.join(os.path.dirname(path), ".req-%d.tmp" % os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def read_hello(rendezvous, max_age, nonce):
    hello_path = os.path.join(rendezvous, "agent-hello.json")
    if not os.path.isfile(hello_path):
        sys.stderr.write("browser_remote: no agent-hello.json in %s\n" % rendezvous)
        sys.exit(4)
    age = time.time() - os.stat(hello_path).st_mtime
    try:
        with open(hello_path, "r", encoding="utf-8") as fh:
            hello = json.loads(fh.read())
    except ValueError as exc:
        sys.stderr.write("browser_remote: agent-hello.json is not strict JSON: %s\n" % exc)
        sys.exit(4)
    if max_age and age > max_age:
        sys.stderr.write("browser_remote: the agent hello is %.0f s old (max %d s); is the Mac agent still running?\n" % (age, max_age))
        sys.exit(4)
    if hello.get("schema") != 1:
        sys.stderr.write("browser_remote: agent hello schema %r is not 1\n" % hello.get("schema"))
        sys.exit(5)
    if nonce and hello.get("nonce") != nonce:
        sys.stderr.write("browser_remote: the agent hello carries another run's nonce\n")
        sys.exit(5)
    return hello, age


def cmd_hello(rendezvous, max_age, nonce):
    hello, age = read_hello(rendezvous, max_age, nonce)
    hello = dict(hello)
    hello["hello_age_seconds"] = round(age, 1)
    json.dump(hello, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def next_request_id(rendezvous):
    """A fresh 4-digit id: every req/resp/processing file of this rendezvous is seen."""
    used = set()
    try:
        for name in os.listdir(rendezvous):
            m = re.match(r"^(?:req|resp)-([0-9]{4})(?:\.processing)?\.json$", name)
            if m:
                used.add(m.group(1))
    except OSError as exc:
        sys.stderr.write("browser_remote: rendezvous %s is not readable: %s\n" % (rendezvous, exc))
        sys.exit(1)
    n = 1
    while "%04d" % n in used and n < 10000:
        n += 1
    if n >= 10000:
        sys.stderr.write("browser_remote: no free request id in %s\n" % rendezvous)
        sys.exit(1)
    return "%04d" % n


def wait_response(rendezvous, req_id, timeout, nonce):
    deadline = time.time() + timeout
    resp_path = os.path.join(rendezvous, "resp-%s.json" % req_id)
    req_path = os.path.join(rendezvous, "req-%s.json" % req_id)
    while time.time() < deadline:
        if os.path.isfile(resp_path):
            try:
                with open(resp_path, "r", encoding="utf-8") as fh:
                    resp = json.loads(fh.read())
            except ValueError as exc:
                sys.stderr.write("browser_remote: response %s is not strict JSON: %s\n" % (resp_path, exc))
                sys.exit(6)
            keys = ",".join(sorted(resp.keys()))
            want = "agent_manifest,browser_json_sha256,exit,files,id,mac_leak_scan,nonce,row,schema,stdout_tail,t_end,t_start"
            if keys != want:
                sys.stderr.write("browser_remote: response carries [%s]; expected [%s]\n" % (keys, want))
                sys.exit(6)
            if resp.get("nonce") != nonce or resp.get("id") != req_id:
                sys.stderr.write("browser_remote: response nonce/id do not bind this run (nonce mismatch); refusing it\n")
                sys.exit(5)
            return resp
        # A disappeared request without a response means the agent refused it: log the
        # state and keep waiting until the timeout (the agent logs its refusal).
        if not os.path.isfile(req_path):
            sys.stderr.write("browser_remote: the request %s disappeared without a response (the agent agent log holds the refusal)\n" % req_path)
        time.sleep(2)
    return None


def cmd_request(rendezvous, nonce, row, timeout):
    if not nonce:
        sys.stderr.write("browser_remote request: --nonce is required\n")
        return 1
    req_id = next_request_id(rendezvous)
    req = {"schema": 1, "id": int(req_id), "row": row, "nonce": nonce}
    _atomic_write(os.path.join(rendezvous, "req-%s.json" % req_id), json.dumps(req) + "\n")
    sys.stderr.write("browser_remote: request %s row %s written (nonce-bound)\n" % (req_id, row))
    resp = wait_response(rendezvous, req_id, timeout, nonce)
    if resp is None:
        hi, age = read_hello(rendezvous, 0, nonce)  # the hello age is part of the failure
        sys.stderr.write("browser_remote: no response in %d s (hello age %.0f s; heartbeat expected every 15 s)\n" % (timeout, age))
        return 3
    json.dump(resp, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 2 if resp.get("exit") not in (0, None) else 0


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__.strip())
        return 1
    cmd = argv[0]
    opts = {"--rendezvous": None, "--nonce": "", "--row": None, "--timeout": "1500", "--max-age": "60"}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in opts:
            i += 1
            if i >= len(argv):
                sys.stderr.write("browser_remote: %s needs a value\n" % arg)
                return 1
            opts[arg] = argv[i]
        else:
            sys.stderr.write("browser_remote: unknown argument %r\n" % arg)
            return 1
        i += 1
    if cmd == "hello":
        return cmd_hello(opts["--rendezvous"], int(opts["--max-age"]), opts.get("--nonce", ""))
    if cmd == "request":
        if not opts["--rendezvous"] or not opts["--row"]:
            sys.stderr.write("browser_remote request: --rendezvous and --row are required\n")
            return 1
        return cmd_request(opts["--rendezvous"], opts["--nonce"], opts["--row"], int(opts["--timeout"]))
    sys.stderr.write("browser_remote: unknown command %r (hello|request)\n" % cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())