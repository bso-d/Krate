#!/usr/bin/env python3
"""Generate Kafbat dual login and the PingFederate identity-provider plan for the Krate realm.

The realm itself (auth/keycloak/krate-realm.json) is planned by `krate identity up`;
this program only adds the pieces that broker PingFederate into that realm.
"""
import argparse
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from configure import kafbat, validate, url  # noqa: E402  (sibling module; explicit path keeps python -I working)


def configs(settings):
    validate(settings, "kafbat")
    for endpoint in ("authorization_url", "token_url", "userinfo_url", "jwks_url"):
        url(settings, endpoint)
    if "offline_access" in settings["scopes"]:
        raise ValueError("dual login does not request refresh tokens; remove offline_access")
    public_url = settings["public_url"].rstrip("/")
    keycloak_url = public_url + "/identity"
    realm_url = keycloak_url + "/realms/krate"
    internal_realm_url = "http://keycloak:8080/identity/realms/krate"
    local_settings = dict(settings, issuer=realm_url, client_id="krate-ui",
                          groups_claim="groups", scopes=["openid", "profile", "email"],
                          authorization_url=realm_url + "/protocol/openid-connect/auth",
                          token_url=internal_realm_url + "/protocol/openid-connect/token",
                          userinfo_url=internal_realm_url + "/protocol/openid-connect/userinfo",
                          jwks_url=internal_realm_url + "/protocol/openid-connect/certs")
    app = json.loads(kafbat(local_settings))
    client = app["auth"]["oauth2"]["client"].pop("pingfederate")
    client.update({"provider": "keycloak", "client-secret": "${KEYCLOAK_KAFBAT_CLIENT_SECRET}",
                   "redirect-uri": public_url + "/login/oauth2/code/keycloak"})
    app["auth"]["oauth2"]["client"]["keycloak"] = client
    app["spring"].pop("config", None)
    app["auth"]["oauth2"].update({"allow-shared-login": True,
                                 "shared-role": "administrator",
                                 "require-mapped-role": True})
    groups = (settings["viewer_group"], settings["admin_group"])
    # Applied to the realm in the SSO phase; the realm plan (local users, clients,
    # groups, sessions) is owned by sso/identity.py and never written here.
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
                        "group": "/" + group}}
            for group in groups],
        # The redirector sends SSO users to PingFederate without a second
        # Keycloak username/password page. The shared Kafbat login is separate.
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
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    created = []
    try:
        result = configs(json.loads(args.settings.read_text()))
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
        print(f"Created Kafbat dual login and the PingFederate identity-provider plan in {args.output_dir}; "
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
