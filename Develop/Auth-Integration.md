# Auth Integration

Uptimer can keep the built-in `ADMIN_TOKEN` login and additionally accept
OIDC access tokens from `auth.jinnkunn.com`.

The integration is intentionally thin:

- Worker admin auth remains centralized in `apps/worker/src/middleware/auth.ts`.
- OIDC verification lives in `apps/worker/src/auth/oidc.ts`.
- Web PKCE login lives in `apps/web/src/auth/oidc.ts`.
- No D1 schema changes are required.
- If the OIDC variables are unset, the legacy admin token behavior is unchanged.

## Auth Server Setup

Register Uptimer as a resource server:

```json
{
  "resource_id": "uptimer",
  "name": "Uptimer",
  "audience": "urn:jinnkunn:uptimer",
  "allowed_scopes": ["uptimer.admin"],
  "risk_level": "medium",
  "require_dpop": false,
  "authorization_details_schema": {}
}
```

Register the Pages admin UI as a public OAuth client:

```json
{
  "name": "Uptimer Admin",
  "redirect_uris": [
    "https://<uptimer-domain>/admin/callback",
    "http://localhost:5173/admin/callback"
  ],
  "scopes": ["openid", "profile", "email", "uptimer.admin"],
  "is_confidential": false,
  "enable_token_exchange": false
}
```

Allow the Uptimer origins in auth-api CORS, for example:

```text
AUTH__CORS__ALLOWED_ORIGINS=https://<uptimer-domain>,http://localhost:5173
```

## Uptimer Worker Variables

Set these Worker variables or secrets:

```text
UPTIMER_AUTH_ISSUER=https://auth.jinnkunn.com
UPTIMER_AUTH_AUDIENCE=urn:jinnkunn:uptimer
UPTIMER_AUTH_REQUIRED_SCOPE=uptimer.admin
UPTIMER_AUTH_ALLOWED_CLIENT_IDS=<registered-uptimer-client-id>
UPTIMER_AUTH_ALLOWED_SUBS=<allowed-auth-user-id>
```

`UPTIMER_AUTH_ALLOWED_ORGS` may be used instead of, or in addition to,
`UPTIMER_AUTH_ALLOWED_SUBS`. Keep at least one subject or organization
allowlist configured unless intentionally setting `UPTIMER_AUTH_ALLOW_ANY_SUBJECT=1`.

Keep `ADMIN_TOKEN` configured for scheduler/internal requests and as an
emergency fallback.

## Uptimer Web Variables

Set these Pages/Vite build-time variables:

```text
VITE_AUTH_ISSUER=https://auth.jinnkunn.com
VITE_AUTH_CLIENT_ID=<registered-uptimer-client-id>
VITE_AUTH_RESOURCE=urn:jinnkunn:uptimer
VITE_AUTH_SCOPE=openid profile email uptimer.admin
VITE_AUTH_REDIRECT_PATH=/admin/callback
```

If `VITE_ADMIN_PATH` is customized, either register that callback path in auth
or set `VITE_AUTH_REDIRECT_PATH` to the matching callback URL path.
