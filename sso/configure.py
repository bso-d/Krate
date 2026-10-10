#!/usr/bin/env python3
"""Generate native OIDC config; no credentials, network calls, or auto-activation."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from identity import kafbat_role  # noqa: E402  (sibling module; explicit path keeps python -I working)


def text(settings, key):
    value = settings.get(key)
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError(f"{key} must be a nonempty single-line string")
    if any(c in value for c in ("$", "{", "}")):
        raise ValueError(f"{key} cannot contain configuration interpolation characters")
    return value


def url(settings, key):
    value = text(settings, key)
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError(f"{key} must be an HTTPS URL without credentials, query or fragment")
    return value


def validate(settings, app):
    if not isinstance(settings, dict):
        raise ValueError("settings must be a JSON object")
    if any("secret" in k.lower() or "password" in k.lower() for k in settings):
        raise ValueError("Keep secrets out of settings; use the mounted secret file")
    url(settings, "issuer")
    public_url = url(settings, "public_url")
    text(settings, "client_id")
    viewer, admin = text(settings, "viewer_group"), text(settings, "admin_group")
    if viewer == admin:
        raise ValueError("Viewer and administrator groups must be different")
    # Deliberately support a top-level claim only; avoids ambiguous nested group
    # extraction and injection into Grafana's JMESPath expression.
    claim = text(settings, "groups_claim")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", claim):
        raise ValueError("groups_claim must be a top-level identifier, e.g. groups")
    scopes = settings.get("scopes")
    if (not isinstance(scopes, list) or "openid" not in scopes or not scopes
            or any(not isinstance(s, str) or not re.fullmatch(r"[\w:.-]+", s) for s in scopes)):
        raise ValueError("scopes must be a list of scope names including openid")
    idle = settings.get("session_idle_minutes", 30)
    if type(idle) is not int or not 1 <= idle <= 1440:
        raise ValueError("session_idle_minutes must be between 1 and 1440")
    if app == "kafbat":
        if urlsplit(public_url).path not in ("", "/"):
            raise ValueError("Kafbat public_url must use the root path")
        clusters = settings.get("clusters")
        if (not isinstance(clusters, list) or not clusters
                or any(not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", c) for c in clusters)
                or len(set(clusters)) != len(clusters)):
            raise ValueError("clusters must contain unique explicit cluster names (no wildcards)")
        endpoints = ("authorization_url", "token_url", "userinfo_url", "jwks_url")
        if any(key in settings for key in endpoints):
            for key in endpoints:
                url(settings, key)
        if type(settings.get("viewer_messages", False)) is not bool:
            raise ValueError("viewer_messages must be boolean")
    elif app == "perses":
        if urlsplit(public_url).path not in ("", "/"):
            raise ValueError("Perses public_url must use the root path, e.g. https://host:3443")
        # OAuth2 Proxy splits allowed groups on commas; the guard matches exact names.
        for key in ("viewer_group", "admin_group"):
            if re.search(r'[,\s"\'\\]', settings[key]):
                raise ValueError(f"{key} must not contain commas, quotes or whitespace")
        if "service_client_id" in settings and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", text(settings, "service_client_id")):
            raise ValueError("service_client_id must be a valid Perses user name")
        proof = settings.get("group_proof_minutes", 15)
        if type(proof) is not int or not 1 <= proof <= 60:
            raise ValueError("group_proof_minutes must be between 1 and 60")
        hours = settings.get("session_hours", 8)
        if type(hours) is not int or not 1 <= hours <= 24:
            raise ValueError("session_hours must be between 1 and 24")
    else:
        for key in ("authorization_url", "token_url", "userinfo_url"):
            url(settings, key)
        # Grafana INI values must not be interpreted as comments or expansions.
        for key in ("viewer_group", "admin_group", "client_id"):
            if any(c in text(settings, key) for c in ('#', ';', '`', '"')):
                raise ValueError(f"{key} contains unsupported INI/JMESPath characters")


def kafbat(settings):
    # The two roles are the ones Krate's own Keycloak plan uses (sso/identity.py):
    # viewers read; message payloads only when the site opts in; KSQL never.
    def role(name, group, admin=False):
        return kafbat_role(name, group, settings["clusters"], admin, settings.get("viewer_messages", False))
    data = {
        "spring": {"config": {"import": "configtree:/etc/krate/auth/secrets/"}},
        "server": {"reactive": {"session": {
            "timeout": f"{settings.get('session_idle_minutes', 30)}m",
            "cookie": {"secure": True, "http-only": True, "same-site": "lax"},
        }}},
        "auth": {"type": "OAUTH2", "oauth2": {"client": {"pingfederate": {
            "provider": "pingfederate", "client-id": settings["client_id"],
            "client-secret": "${ping.client-secret}", "client-name": "Company sign-in",
            "scope": settings["scopes"], "issuer-uri": settings["issuer"],
            "redirect-uri": settings["public_url"].rstrip("/") + "/login/oauth2/code/pingfederate",
            "authorization-grant-type": "authorization_code", "user-name-attribute": "sub",
            "custom-params": {"type": "oauth", "roles-field": settings["groups_claim"]},
        }}}},
        "rbac": {"roles": [role("viewer", settings["viewer_group"]),
                            role("administrator", settings["admin_group"], True)]},
    }
    oauth = data["auth"]["oauth2"]
    oauth["require-mapped-role"] = True
    client = oauth["client"]["pingfederate"]
    for setting, key in (("authorization_url", "authorization-uri"), ("token_url", "token-uri"),
                         ("userinfo_url", "user-info-uri"), ("jwks_url", "jwk-set-uri")):
        if setting in settings:
            client[key] = settings[setting]
    # JSON is valid YAML; use the standard serializer instead of templating YAML.
    return json.dumps(data, indent=2) + "\n"


def grafana(settings):
    claim = settings["groups_claim"]
    # JSON literals in backticks are JMESPath string literals, safely serialized.
    def contains(group):
        return f"contains({claim}[*], `{json.dumps(group)}`)"
    expression = (f"{contains(settings['admin_group'])} && 'Admin' || "
                  f"{contains(settings['viewer_group'])} && 'Viewer' || ''")
    public_url = settings["public_url"].rstrip("/") + "/"
    return f"""; Generated by Krate. Configure an approved HTTPS reverse proxy before activation.
[server]
root_url = {public_url}
serve_from_sub_path = {str(urlsplit(public_url).path != '/').lower()}
[security]
cookie_secure = true
cookie_samesite = lax
[auth]
disable_login_form = true
login_maximum_inactive_lifetime_duration = {settings.get('session_idle_minutes', 30)}m
[auth.basic]
enabled = false
[auth.generic_oauth]
enabled = true
name = Company sign-in
allow_sign_up = true
client_id = {settings['client_id']}
client_secret = $__file{{/etc/krate/auth/secrets/grafana.client-secret}}
scopes = {' '.join(settings['scopes'])}
auth_url = {settings['authorization_url']}
token_url = {settings['token_url']}
api_url = {settings['userinfo_url']}
login_attribute_path = sub
groups_attribute_path = {claim}
role_attribute_path = {expression}
role_attribute_strict = true
skip_org_role_sync = false
allow_assign_grafana_admin = false
use_pkce = true
use_refresh_token = false
tls_skip_verify_insecure = false
"""


def perses(settings):
    """Site settings read by monitoring/render.py for Perses SSO."""
    keys = ("issuer", "public_url", "client_id", "viewer_group", "admin_group", "groups_claim",
            "scopes", "service_client_id", "group_proof_minutes", "session_hours")
    site = {key: settings[key] for key in keys if key in settings}
    site["public_url"] = site["public_url"].rstrip("/")
    return json.dumps(site, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("kafbat", "grafana", "perses"), required=True)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        settings = json.loads(args.settings.read_text())
        validate(settings, args.app)
        content = {"kafbat": kafbat, "grafana": grafana, "perses": perses}[args.app](settings)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # No implicit overwrite of an active deployment's authentication config.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w") as output:
            output.write(content)
            os.fchmod(output.fileno(), 0o644)  # Non-secret config readable in container.
        print(f"Created {args.output}; no services changed. Client secret must be provisioned separately.")
    except (OSError, ValueError) as exc:
        print(f"SSO configuration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
