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
                           firstBrokerLoginFlowAlias names the flow below; `enabled`,
                           `trustEmail` and `storeToken` are identity.BROKER_PROVIDER_FLAGS
                           (trustEmail true: Keycloak carries the e-mail verification
                           PingFederate asserts, which the Phase 4 UIs require).
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
  mfa_not_asserted         the site's explicit MFA stance (enforce-if-asserted): with `mfa_not_asserted`
                           true the plan carries this top-level key (never sent to Keycloak) and no claim
                           filter ("MFA for SSO users is enforced at PingFederate only"). With the site keys
                           `mfa_claim_name`/`mfa_claim_value` (set together) the provider's config instead
                           gains `filteredByClaim`, `claimFilterName` and `claimFilterValue`, Keycloak's
                           "Verify essential claim" (a missing claim and an unmatched value both refuse the
                           brokered sign-in before any user is created). The site file must state one of
                           the two stances: `krate auth configure` refuses a site file that states neither,
                           and the preflight refuses a plan file that does.
                           The three provider keys are managed: a plan without the pair makes `auth apply`
                           clear them from a live provider (the update replaces the provider's configuration).

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
    """{relative path: JSON data} for a site file; `env` is the parsed .env mapping (groups, idle limit, session maximum, viewer opt-in)."""
    validate(settings, "kafbat", broker=True)
    for endpoint in ("authorization_url", "token_url", "userinfo_url", "jwks_url"):
        url(settings, endpoint)
    # The site's MFA stance (enforce-if-asserted): the essential-claim filter keys go on the
    # provider's config when the site names the claim PingFederate asserts; `mfa_not_asserted`
    # is recorded as a top-level plan key ("MFA enforced at Ping only") that is never sent to
    # Keycloak. A site file that states neither is refused here; a plan file that does is refused by the preflight.
    pair = "mfa_claim_name" in settings
    not_asserted = bool(settings.get("mfa_not_asserted", False))
    if not pair and not not_asserted:
        raise identity.MfaStanceError(f"the site file states no MFA stance: {identity.MFA_STANCE_HINT}; add one of the two and run krate auth configure again")
    if "offline_access" in settings["scopes"]:
        raise ValueError("dual login does not request refresh tokens; remove offline_access")
    # One source for both sides of a session limit and for the viewer's message access.
    for key, env_key in (("session_idle_minutes", "KEYCLOAK_SESSION_IDLE_MINUTES"),
                         ("session_max_hours", "KEYCLOAK_SESSION_MAX_HOURS"),
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
    # the realm group of the same role, which is what Kafbat's roles read. The
    # provider's fixed flags come from identity.BROKER_PROVIDER_FLAGS, which
    # broker_plan() validates, so a plan can only carry the Krate values.
    identity_provider = {
        "identityProviders": [{"alias": identity.BROKER_ALIAS, "displayName": "Company sign-in",
                               "providerId": "oidc", **identity.BROKER_PROVIDER_FLAGS,
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
        "authenticatorConfig": identity.planned_authenticator_config(),
        "authenticationFlows": identity.planned_flows(),
        "browserFlow": identity.BROWSER_FLOW,
        "truststore": truststore,
    }
    if pair:
        identity_provider["identityProviders"][0]["config"].update(
            {"filteredByClaim": "true", "claimFilterName": settings["mfa_claim_name"],
             "claimFilterValue": settings["mfa_claim_value"]})
    elif not_asserted:
        identity_provider[identity.MFA_NOT_ASSERTED_KEY] = True
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
