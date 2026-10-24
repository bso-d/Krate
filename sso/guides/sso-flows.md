# Sign-in and enrollment

These flows apply to EPC and regular Krate.

```mermaid
sequenceDiagram
    actor User
    participant UI as Kafbat
    participant KC as Keycloak
    participant PF as PingFederate
    participant AD as Active Directory
    alt Shared Admin login (SSO off: no Keycloak)
        User->>UI: Enter shared username and password
        UI->>UI: Check app credential and grant Admin
    else SSO login (Kafbat has no form login)
        User->>UI: Click Log in with Keycloak
        UI-->>User: Redirect to Keycloak
        User->>KC: Start OIDC sign-in
        KC-->>User: Redirect to PingFederate
        User->>PF: Use enterprise session or sign in
        PF->>AD: Apply identity and group policy
        PF-->>KC: Return identity and group claims
        KC-->>UI: Return signed OIDC identity and groups
        UI->>UI: Map Viewer or Admin, deny unmapped users
    end
    UI-->>User: Start app session
```

```mermaid
flowchart LR
    A[Existing AD user] --> B[IAM grants app access and Viewer or Admin group]
    B --> C[User presses Log in with Keycloak]
    C --> D[PingFederate authenticates user]
    D --> E[Keycloak maps AD group]
    E --> F{Kafbat group mapping}
    F -->|Viewer| G[Read all configured clusters]
    F -->|Admin or both| H[Full access]
    F -->|Neither| I[Access denied]
```

There is no per-user enrollment in Kafbat. A group change takes effect at a
new sign-in. For urgent revocation, end active application sessions as well.

## Automatic IdP Fallback and Recovery

```mermaid
sequenceDiagram
    participant IdP as PingFederate (Enterprise IdP)
    participant Watch as idp-watch (Watcher Daemon)
    participant KC as Keycloak (Realm krate)
    actor Op as Local Operator
    participant UI as Kafbat UI

    Note over IdP,Watch: IdP Outage Occurs
    loop Health Probe Cycle (every 10s)
        Watch->>IdP: GET discovery / JWKS / token
        IdP--xWatch: Network timeout or 5xx outage
    end
    Note over Watch: Threshold reached (2 failures + dwell)
    Watch->>KC: PUT /admin/realms/krate/... (enabled: false)
    KC-->>Watch: 204 No Content

    Note over Op,KC: Emergency Break-Glass Sign-in
    Op->>UI: Click Log in with Keycloak
    UI-->>Op: 302 Redirect to Keycloak /auth
    Op->>KC: GET /protocol/openid-connect/auth
    Note over KC: IdP disabled → fall through to krate forms
    KC-->>Op: 200 kc-form-login + Warning Banner
    Op->>KC: POST credentials (username/password + OTP)
    KC-->>UI: 302 Authorization code
    UI-->>Op: Authenticated session established

    Note over IdP,Watch: IdP Service Restored
    loop Health Probe Cycle (every 10s)
        Watch->>IdP: GET discovery / JWKS / token
        IdP-->>Watch: 200 OK (Application reachable)
    end
    Note over Watch: Recovery threshold reached (2 successes + dwell)
    Watch->>KC: PUT /admin/realms/krate/... (enabled: true)
    KC-->>Watch: 204 No Content
    Note over KC,UI: Steady-state restored: default path redirects to IdP (303)
```
