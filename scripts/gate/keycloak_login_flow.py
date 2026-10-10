#!/usr/bin/env python3
"""Headless Keycloak browser-flow probe for the identity gate (no browser; HTTP only).

Drives the realm's authorization-code flow with PKCE through the nginx proxy exactly
as a browser would: login form, required actions (TOTP enrolment, forced password
update), OTP prompt, code exchange. Used by scripts/gate-identity.sh.

  enrol  --base URL --user U --password-env VAR --client-secret-env VAR --state FILE
         First login with the temporary password: completes CONFIGURE_TOTP and
         UPDATE_PASSWORD, then proves that a second login asks for the OTP, that a
         wrong OTP is refused and that the old password is refused. Writes the new
         password and TOTP secret to FILE (mode 600). Prints the ID-token claims.
  login  --base URL --state FILE --client-secret-env VAR [--expect ok|refused]
         Full login (password + OTP) for an enrolled user; prints claims or REFUSED.
  login  --base URL --user U --password-env VAR --client-secret-env VAR --expect refused
         Login attempt with a plain password (wrong password, disabled user, ...).

Secrets are read from the environment variables named on the command line, never
from argv. Nothing secret is printed.
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REALM = "krate"
CLIENT = "krate-ui"


class Flow:
    def __init__(self, base, client_secret):
        self.base = base.rstrip("/") + f"/identity/realms/{REALM}"
        self.redirect = base.rstrip("/") + "/login/oauth2/code/keycloak"
        self.client_secret = client_secret
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # fixture proxy uses a self-signed certificate
        self.jar = http.cookiejar.CookieJar()

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            # noinspection PyMethodMayBeStatic
            def redirect_request(self, *_args, **_kwargs):  # overrides an instance method
                return None

        self.opener = urllib.request.build_opener(
            NoRedirect, urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ctx))

    def req(self, url, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
        r = urllib.request.Request(url, data=body, headers=headers)
        try:
            resp = self.opener.open(r, timeout=30)
            st, h, text = resp.status, resp.headers, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            st, h, text = e.code, e.headers, e.read().decode(errors="replace")
        # Follow redirects that stay inside the realm (required-action pages); stop at the client redirect.
        if st in (302, 303) and h.get("Location", "").startswith(self.base + "/"):
            return self.req(h["Location"])
        return st, h, text

    @staticmethod
    def form_action(page):
        m = re.search(r'<form[^>]+action="([^"]+)"', page)
        if not m:
            raise AssertionError("no form in page: " + page[:300])
        return html.unescape(m.group(1))

    @staticmethod
    def totp(secret_b32, t=None):
        key = base64.b32decode(secret_b32.replace(" ", "").upper())
        counter = int((t or time.time()) // 30)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        o = digest[-1] & 15
        return "%06d" % ((struct.unpack(">I", digest[o:o + 4])[0] & 0x7fffffff) % 1000000)

    def start_auth(self):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = dict(client_id=CLIENT, response_type="code", scope="openid", redirect_uri=self.redirect,
                 state=secrets.token_hex(8), nonce=secrets.token_hex(8),
                 code_challenge=challenge, code_challenge_method="S256")
        st, h, page = self.req(self.base + "/protocol/openid-connect/auth?" + urllib.parse.urlencode(q))
        if not (st == 200 and 'id="kc-form-login"' in page):
            raise AssertionError(f"expected the login form, got {st}: {page[:200]}")
        return verifier, self.form_action(page)

    def exchange(self, location, verifier):
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]
        st, h, body = self.req(self.base + "/protocol/openid-connect/token", dict(
            grant_type="authorization_code", code=code, redirect_uri=self.redirect, client_id=CLIENT,
            client_secret=self.client_secret, code_verifier=verifier))
        if st != 200:
            raise AssertionError(f"code exchange failed {st}: {body[:200]}")
        tok = json.loads(body)
        seg = tok["id_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        out = {k: claims.get(k) for k in ("iss", "aud", "sub", "preferred_username", "groups", "acr")}
        out["expires_in"] = tok["expires_in"]
        out["scope"] = tok.get("scope")
        return out

    def password_step(self, action, user, password):
        return self.req(action, dict(username=user, password=password, credentialId=""))

    def is_code_redirect(self, st, h):
        return st in (302, 303) and h.get("Location", "").startswith(self.redirect)


def wait_next_totp_step():
    time.sleep(30 - time.time() % 30 + 1)  # a TOTP code is single-use; wait for the next 30 s step


def do_enrol(a):
    flow = Flow(a.base, os.environ[a.client_secret_env])
    temp_pw = os.environ[a.password_env]
    new_pw = secrets.token_urlsafe(14)
    log("login 1: temporary password, pending required actions")
    verifier, action = flow.start_auth()
    st, h, page = flow.password_step(action, a.user, temp_pw)
    secret_b32 = None
    seen = []
    for _ in range(3):  # required actions in whatever order the realm presents them
        if st == 200 and 'name="totpSecret"' in page:
            found = re.search(r'name="totpSecret"[^>]*value="([^"]+)"', page)
            if not found:
                raise AssertionError("TOTP page without a totpSecret value: " + page[:200])
            raw = html.unescape(found.group(1))
            secret_b32 = base64.b32encode(raw.encode()).decode()  # Keycloak keys HmacOTP on the raw secret's bytes
            st, h, page = flow.req(flow.form_action(page), {"totp": flow.totp(secret_b32), "totpSecret": raw,
                                                           "userLabel": "gate", "logout-sessions": "on"})
            seen.append("CONFIGURE_TOTP")
            continue
        if st == 200 and 'name="password-new"' in page:
            st, h, page = flow.req(flow.form_action(page), {"password-new": new_pw, "password-confirm": new_pw})
            seen.append("UPDATE_PASSWORD")
            continue
        break
    if not flow.is_code_redirect(st, h):
        raise AssertionError(f"expected redirect with code after required actions {seen}, got {st}: {page[:300]}")
    if seen != ["CONFIGURE_TOTP", "UPDATE_PASSWORD"] and sorted(seen) != ["CONFIGURE_TOTP", "UPDATE_PASSWORD"]:
        raise AssertionError(f"required actions seen: {seen}")
    claims1 = flow.exchange(h["Location"], verifier)
    log(f"required actions completed in order {seen}")

    flow.jar.clear()
    log("login 2: new password, OTP required, wrong OTP refused")
    verifier, action = flow.start_auth()
    st, h, page = flow.password_step(action, a.user, new_pw)
    if not (st == 200 and 'name="otp"' in page and "password-new" not in page):
        raise AssertionError(f"expected the OTP form, got {st}: {page[:300]}")
    st, h, page = flow.req(flow.form_action(page), {"otp": "000000"})
    if not (st == 200 and 'name="otp"' in page and "nvalid" in page):
        raise AssertionError(f"expected wrong-OTP refusal, got {st}: {page[:300]}")
    wait_next_totp_step()
    st, h, page = flow.req(flow.form_action(page), {"otp": flow.totp(secret_b32)})
    if not flow.is_code_redirect(st, h):
        raise AssertionError(f"expected redirect with code after OTP, got {st}: {page[:300]}")
    claims2 = flow.exchange(h["Location"], verifier)

    flow.jar.clear()
    log("login 3: old temporary password must be refused")
    verifier, action = flow.start_auth()
    st, h, page = flow.password_step(action, a.user, temp_pw)
    if not (st == 200 and 'id="kc-form-login"' in page and 'name="otp"' not in page):
        raise AssertionError(f"expected the login form again, got {st}: {page[:300]}")

    fd = os.open(a.state, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"user": a.user, "password": new_pw, "totp": secret_b32}, f)
    print(json.dumps({"result": "ENROLLED", "required_actions": seen, "claims": claims1,
                      "second_login_claims": claims2}))


def do_login(a):
    flow = Flow(a.base, os.environ[a.client_secret_env])
    if a.state:
        with open(a.state) as f:
            s = json.load(f)
        user, password, totp_secret = s["user"], s["password"], s["totp"]
    else:
        user, password, totp_secret = a.user, os.environ[a.password_env], None
    verifier, action = flow.start_auth()
    st, h, page = flow.password_step(action, user, password)
    if st == 200 and 'name="otp"' in page and totp_secret:
        # --totp-offset N uses the code of the Nth neighbouring 30-second step (the realm's look-ahead window).
        st, h, page = flow.req(flow.form_action(page), {"otp": flow.totp(totp_secret, time.time() + 30 * a.totp_offset)})
    if flow.is_code_redirect(st, h):
        claims = flow.exchange(h["Location"], verifier)
        if a.expect == "refused":
            raise AssertionError("login succeeded but was expected to be refused")
        print(json.dumps({"result": "OK", "claims": claims}))
        return
    # Refused: still on a Keycloak page (login form with an error, or an error page).
    # keycloak.v2 theme (PatternFly 5): the message sits in #input-error-container-<field> as helper text;
    # the error page uses #kc-error-message. Verified in Chrome DevTools on 2026-10-10 (harness/gate-receipts/devtools-walk-02-wrong-password.png).
    msg = (re.search(r'id="input-error[^"]*".*?helper-text__item-text[^>]*>\s*([^<]*?)\s*<', page, re.S)
           or re.search(r'id="kc-error-message".*?<p[^>]*>([^<]*)<', page, re.S)
           or re.search(r'<span[^>]*kc-feedback-text[^>]*>([^<]*)<', page))
    reason = html.unescape(msg.group(1).strip()) if msg else f"status {st}"
    if a.expect == "ok":
        raise AssertionError(f"login refused: {reason}")
    print(json.dumps({"result": "REFUSED", "reason": reason, "status": st}))


def log(msg):
    print("  " + msg, file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    e.add_argument("--base", required=True)
    e.add_argument("--user", required=True)
    e.add_argument("--password-env", required=True)
    e.add_argument("--client-secret-env", required=True)
    e.add_argument("--state", required=True)
    l = sub.add_parser("login")
    l.add_argument("--base", required=True)
    l.add_argument("--state")
    l.add_argument("--user")
    l.add_argument("--password-env")
    l.add_argument("--client-secret-env", required=True)
    l.add_argument("--expect", choices=["ok", "refused"], default="ok")
    l.add_argument("--totp-offset", type=int, default=0, help="use the code of this neighbouring 30-second step (default: current)")
    a = p.parse_args()
    if a.cmd == "login" and not a.state and not (a.user and a.password_env):
        p.error("login needs --state or --user with --password-env")
    try:
        do_enrol(a) if a.cmd == "enrol" else do_login(a)
    except AssertionError as exc:
        print(json.dumps({"result": "FAIL", "error": str(exc)[:400]}))
        sys.exit(1)


if __name__ == "__main__":
    main()
