#!/usr/bin/env python3
"""Generate Kafbat's Keycloak login and the PingFederate identity-provider plan for the Krate realm.

The realm itself (auth/keycloak/krate-realm.json) is planned by `krate identity up`
and Kafbat's runtime.yml by the same module (sso/identity.py); this program adds
only the pieces that broker PingFederate into that realm.

Plan file schema (auth/keycloak/pingfederate-idp.json), Keycloak's export shape, applied
by `krate auth apply` and `krate identity up` (identity_apply_idp) and read through
`identity.py broker`:

  identityProviders        one IdentityProviderRepresentation, alias `pingfederate`;
                           config.clientSecret is the ${PING_KEYCLOAK_CLIENT_SECRET}
                           placeholder, replaced from the environment at apply time;
                           firstBrokerLoginFlowAlias names the flow below.
  identityProviderMappers  two oidc-advanced-group-idp-mapper entries, matched by `name`.
  authenticatorConfig      [{alias, config}] for the identity-provider-redirector.
  authenticationFlows      AuthenticationFlowRepresentation list; `topLevel` true for the
                           flows the realm binds, false for sub-flows. Each execution is an
                           AuthenticationExecutionExportRepresentation: either an authenticator
                           ({authenticator, requirement, priority, userSetupAllowed,
                           optional authenticatorConfig alias}) or a sub-flow reference
                           ({authenticatorFlow: true, flowAlias, requirement, priority}), whose
                           flow is another entry of the list. Order is the apply order.
  browserFlow              the alias the realm's browser binding is set to.
  truststore               `local` (default; site key `idp_truststore`): the preflight requires a CA
                           file in auth/keycloak/truststores when the provider is not on the public
                           host; `system`: the JVM default truststore is relied on (public CA).

Decisions D1-D4 (sso/guides/dual-login.md, owner to confirm) shape the flows:
  "krate first broker login" (D2): idp-create-user-if-unique REQUIRED, so an SSO identity never
      links to a local account; a clash is an error page.
  "krate browser" (D3): auth-cookie ALT 10, identity-provider-redirector ALT 20 with
      defaultProvider pingfederate, sub-flow "krate forms" ALT 30 = auth-username-password-form
      REQUIRED 10 + sub-flow "krate otp" CONDITIONAL 20 = conditional-user-configured REQUIRED 10
      + auth-otp-form REQUIRED 20. The forms are reached only with `?kc_idp_hint=` (empty).
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
    truststore = settings.get("idp_truststore", "local")
    if truststore not in identity.TRUSTSTORE_MODES:
        raise ValueError("idp_truststore must be local (CA file in auth/keycloak/truststores) or system (JVM default truststore)")
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
        "identityProviders": [{"alias": identity.BROKER_ALIAS, "displayName": "Company sign-in",
                               "providerId": "oidc", "enabled": True,
                               "trustEmail": False, "storeToken": False,
                               "firstBrokerLoginFlowAlias": identity.FIRST_BROKER_FLOW,
                               "config": {"clientId": settings["client_id"],
                                          "clientSecret": identity.BROKER_SECRET,
                                          "issuer": settings["issuer"],
                                          "authorizationUrl": settings["authorization_url"],
                                          "tokenUrl": settings["token_url"],
                                          "userInfoUrl": settings["userinfo_url"],
                                          "jwksUrl": settings["jwks_url"],
                                          "useJwksUrl": "true", "validateSignature": "true",
                                          "defaultScope": " ".join(settings["scopes"]),
                                          "syncMode": "FORCE"}}],
        "identityProviderMappers": [
            {"name": group + " from PingFederate", "identityProviderAlias": identity.BROKER_ALIAS,
             "identityProviderMapper": "oidc-advanced-group-idp-mapper",
             "config": {"claims": json.dumps([{"key": settings["groups_claim"],
                                                "value": group}]),
                        "syncMode": "FORCE", "are.claim.values.regex": "false",
                        "group": "/" + realm_group}}
            for group, realm_group in ((settings["viewer_group"], viewer_group),
                                       (settings["admin_group"], admin_group))],
        # The redirector sends SSO users to PingFederate without a second
        # Keycloak username/password page.
        "authenticatorConfig": [{"alias": identity.REDIRECT_CONFIG,
                                 "config": {"defaultProvider": identity.BROKER_ALIAS}}],
        "authenticationFlows": flows(),
        "browserFlow": identity.BROWSER_FLOW,
        "truststore": truststore,
    }
    return {"ui/runtime.yml": app, "keycloak/pingfederate-idp.json": identity_provider}


def execution(authenticator, requirement, priority, config=None):
    item = {"authenticator": authenticator, "requirement": requirement, "priority": priority,
            "authenticatorFlow": False, "userSetupAllowed": False}
    if config:
        item["authenticatorConfig"] = config
    return item


def subflow(alias, requirement, priority):
    return {"authenticatorFlow": True, "flowAlias": alias, "requirement": requirement,
            "priority": priority, "userSetupAllowed": False}


def flow(alias, description, executions, top_level):
    return {"alias": alias, "description": description, "providerId": "basic-flow",
            "topLevel": top_level, "builtIn": False, "authenticationExecutions": executions}


def flows():
    """The realm's browser flow (D3) and first-broker-login flow (D2); parents before their sub-flows."""
    return [
        flow(identity.BROWSER_FLOW, "Krate: cookie, then PingFederate; local users with ?kc_idp_hint= (empty)",
             [execution("auth-cookie", "ALTERNATIVE", 10),
              execution("identity-provider-redirector", "ALTERNATIVE", 20, identity.REDIRECT_CONFIG),
              subflow(identity.FORMS_FLOW, "ALTERNATIVE", 30)], True),
        flow(identity.FORMS_FLOW, "local users: password, then OTP when enrolled",
             [execution("auth-username-password-form", "REQUIRED", 10),
              subflow(identity.OTP_FLOW, "CONDITIONAL", 20)], False),
        flow(identity.OTP_FLOW, "OTP when the user has one",
             [execution("conditional-user-configured", "REQUIRED", 10),
              execution("auth-otp-form", "REQUIRED", 20)], False),
        flow(identity.FIRST_BROKER_FLOW, "Krate: create the brokered user; never link to a local account",
             [execution("idp-create-user-if-unique", "REQUIRED", 10)], True),
    ]



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
