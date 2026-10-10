#!/usr/bin/env python3
"""Generate Kafbat's Keycloak login and the PingFederate identity-provider plan for the Krate realm.

The realm itself (auth/keycloak/krate-realm.json) is planned by `krate identity up`
and Kafbat's runtime.yml by the same module (sso/identity.py); this program adds
only the pieces that broker PingFederate into that realm.
"""
import argparse
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import identity  # noqa: E402  (sibling modules; explicit path keeps python -I working)
from configure import validate, url  # noqa: E402


def configs(settings, env=None):
    """{relative path: JSON data} for a site file; `env` is the parsed .env mapping (groups, idle limit, viewer opt-in)."""
    validate(settings, "kafbat")
    for endpoint in ("authorization_url", "token_url", "userinfo_url", "jwks_url"):
        url(settings, endpoint)
    if "offline_access" in settings["scopes"]:
        raise ValueError("dual login does not request refresh tokens; remove offline_access")
    # One source for both sides of a session limit and for the viewer's message access.
    for key, env_key in (("session_idle_minutes", "KEYCLOAK_SESSION_IDLE_MINUTES"),
                         ("viewer_messages", identity.VIEWER_MESSAGES_KEY)):
        if key in settings:
            raise ValueError(f"{key} is read from .env: krate config set {env_key}=...; remove it from the site file")
    env = dict(env or {})
    public_url = settings["public_url"].rstrip("/")
    # Kafbat's runtime.yml is the same plan `krate auth configure` writes without a
    # site file; the realm stays the Keycloak issuer, PingFederate is brokered behind it.
    app = identity.runtime(identity.runtime_settings(env, settings["clusters"], origin=public_url))
    viewer_group, admin_group = identity.group_names(env)
    # Applied to the realm in the SSO phase; the realm plan (local users, clients,
    # groups, sessions) is owned by sso/identity.py and never written here. The
    # mappers put a PingFederate user whose claim names the site's AD group into
    # the realm group of the same role, which is what Kafbat's roles read.
    identity_provider = {
        "identityProviders": [{"alias": "pingfederate", "displayName": "Company sign-in",
                               "providerId": "oidc", "enabled": True,
                               "trustEmail": False, "storeToken": False,
                               "firstBrokerLoginFlowAlias": "first broker login",
                               "config": {"clientId": settings["client_id"],
                                          "clientSecret": "${PING_KEYCLOAK_CLIENT_SECRET}",
                                          "issuer": settings["issuer"],
                                          "authorizationUrl": settings["authorization_url"],
                                          "tokenUrl": settings["token_url"],
                                          "userInfoUrl": settings["userinfo_url"],
                                          "jwksUrl": settings["jwks_url"],
                                          "useJwksUrl": "true", "validateSignature": "true",
                                          "defaultScope": " ".join(settings["scopes"]),
                                          "syncMode": "FORCE"}}],
        "identityProviderMappers": [
            {"name": group + " from PingFederate", "identityProviderAlias": "pingfederate",
             "identityProviderMapper": "oidc-advanced-group-idp-mapper",
             "config": {"claims": json.dumps([{"key": settings["groups_claim"],
                                                "value": group}]),
                        "syncMode": "FORCE", "are.claim.values.regex": "false",
                        "group": "/" + realm_group}}
            for group, realm_group in ((settings["viewer_group"], viewer_group),
                                       (settings["admin_group"], admin_group))],
        # The redirector sends SSO users to PingFederate without a second
        # Keycloak username/password page.
        "authenticatorConfig": [{"alias": "PingFederate redirect",
                                 "config": {"defaultProvider": "pingfederate"}}],
        "authenticationFlows": [{"alias": "krate browser", "providerId": "basic-flow",
                                 "topLevel": True, "builtIn": False,
                                 "authenticationExecutions": [
                                     {"authenticator": "auth-cookie", "requirement": "ALTERNATIVE",
                                      "priority": 10, "userSetupAllowed": False},
                                     {"authenticator": "identity-provider-redirector",
                                      "authenticatorConfig": "PingFederate redirect",
                                      "requirement": "ALTERNATIVE", "priority": 20,
                                      "userSetupAllowed": False}]}],
        "browserFlow": "krate browser",
    }
    return {"ui/runtime.yml": app, "keycloak/pingfederate-idp.json": identity_provider}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, help="the installation's .env (group names, session idle limit, viewer opt-in)")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    created = []
    try:
        env = identity.read_env(args.env_file) if args.env_file else {}
        result = configs(json.loads(args.settings.read_text()), env)
        for name, data in result.items():
            identity.assert_redacted(json.dumps(data), env)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name in result:
            if (args.output_dir / name).exists():
                raise ValueError(f"Refusing to replace {args.output_dir / name}")
        for name, data in result.items():
            path = args.output_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            created.append(path)
            with os.fdopen(fd, "w") as output:
                output.write(json.dumps(data, indent=2) + "\n")
                os.fchmod(output.fileno(), 0o644)
        print(f"Created Kafbat's Keycloak login (ui/runtime.yml) and the PingFederate identity-provider plan in {args.output_dir}; "
              "no services changed.")
        print("The realm file auth/keycloak/krate-realm.json is owned by krate identity up; "
              "keycloak/pingfederate-idp.json is applied to the realm in the SSO phase (Phase 3).")
        print("Review the generated files, run krate identity up, then krate auth apply "
              "(Compose 2.20.2 or newer); it asks for the PingFederate client secret.")
    except (OSError, ValueError) as exc:
        for path in created:
            path.unlink()
        print(f"Dual login configuration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
