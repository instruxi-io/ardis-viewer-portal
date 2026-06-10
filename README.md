# ardis-viewer-portal

Credential viewer for recipients of Ardis credential shares. Deployed on Cloudflare Pages.

A recipient opens a share link, proves their email identity via OTP, and views the credential.
No account is created. Session is memory-only — tab close = access gone.

---

## Environments

> **All active work uses staging. Production URLs are listed for reference only.**
> Never point anything at production without an explicit decision to do so.

| | Staging (active) | Production (not in use) |
|---|---|---|
| Viewer portal | `https://ardis-viewer-portal.pages.dev` | TBD |
| ardis-ms (API) | `https://ardis-ms-ix.fly.dev` | TBD |
| Enforcer gateway (OTP auth) | `https://gateway-staging.instruxi.dev/api/v1/enforcer` | `https://gateway.instruxi.dev/api/v1/enforcer` |

If you see `gateway.instruxi.dev` without `-staging`, that is the production gateway. Do not use it.

---

## Environment variables (Cloudflare Pages build settings)

| Variable | Staging value | Notes |
|---|---|---|
| `VITE_ARDIS_API_BASE` | `https://ardis-ms-ix.fly.dev` | ardis-ms base — no `/api/v1/ardis` suffix |
| `VITE_ENFORCER_BASE` | `https://gateway-staging.instruxi.dev/api/v1/enforcer` | Used for OTP auth only. Must match what ardis-ms validates against. |

These are baked into the bundle at build time. Changing them requires a Cloudflare Pages redeploy.

---

## Share access flow

```
1. Recipient opens share URL:  /view/{guid}
2. Viewer portal calls:        GET {VITE_ARDIS_API_BASE}/api/v1/ardis/public/share/{guid}
3. If share has a recipient:   ardis-ms returns 401 { otp_required: true, email_hint: "h***@..." }
4. OTP gate shown:             recipient enters their email
5. Viewer portal calls:        POST {VITE_ENFORCER_BASE}/auth/login  (tenant: CredPass-Viewer-Portal)
6. Recipient enters OTP code:  POST {VITE_ENFORCER_BASE}/auth/login/verify
7. Viewer portal retries:      GET /public/share/{guid}  with Bearer JWT
8. ardis-ms validates JWT:     calls GET {ENFORCER_BASE}/users/me server-side, checks email matches
9. Credential returned and rendered in browser
```

The Storj sub-grant never leaves ardis-ms. The viewer receives only the credential JSON over TLS.

---

## OTP tenant

The OTP flow uses a dedicated Enforcer tenant: **`CredPass-Viewer-Portal`**
(tenant ID: `4b59111a-c4a3-49d4-b554-ca9e58bd51a8` on staging).

This tenant must have a **SendGrid email connection** configured to deliver OTP codes.
Without it, `POST /auth/login` returns `"Failed to send OTP email"` and the viewer is blocked.
Status: SendGrid connection pending — contact Austin to provision.

---

## Local dev

```bash
npm install
cp .env .env.local   # already has staging values
npm run dev
```

The dev server runs at `http://localhost:5173`. Share links from the staging ardis-ms will work if you
set `VITE_ARDIS_API_BASE=https://ardis-ms-ix.fly.dev` (cross-origin is allowed by ardis-ms CORS config).
