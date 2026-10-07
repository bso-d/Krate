#!/usr/bin/env python3
"""Generate native OIDC config; no credentials, network calls, or auto-activation."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


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
        if type(settings.get("viewer_messages", True)) is not bool:
            raise ValueError("viewer_messages must be boolean")
    else:
        for key in ("authorization_url", "token_url", "userinfo_url"):
            url(settings, key)
        # Grafana INI values must not be interpreted as comments or expansions.
        for key in ("viewer_group", "admin_group", "client_id"):
            if any(c in text(settings, key) for c in ('#', ';', '`', '"')):
                raise ValueError(f"{key} contains unsupported INI/JMESPath characters")


def kafbat(settings):
    def role(name, group, admin=False):
        topic_actions = ["view", "analysis_view"]
        if settings.get("viewer_messages", True):
            topic_actions.append("messages_read")
        permissions = []
        for resource in ("applicationconfig", "clusterconfig", "topic", "consumer",
                         "schema", "connect", "connector", "acl", "audit", "client_quotas"):
            permission = {"resource": resource, "actions": "all" if admin else ["view"]}
            if resource in ("topic", "consumer", "schema", "connect", "connector"):
                permission["value"] = ".*"
            if resource == "topic" and not admin:
                permission["actions"] = topic_actions
            permissions.append(permission)
        # KSQL has execute only, which also permits mutations; never grant it to Viewer.
        if admin:
            permissions.append({"resource": "ksql", "actions": "all"})
        return {
            "name": name, "clusters": settings["clusters"],
            "subjects": [{"provider": "oauth", "type": "role", "value": group, "regex": False}],
            "permissions": permissions,
        }
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("kafbat", "grafana"), required=True)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        settings = json.loads(args.settings.read_text())
        validate(settings, args.app)
        content = kafbat(settings) if args.app == "kafbat" else grafana(settings)
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
