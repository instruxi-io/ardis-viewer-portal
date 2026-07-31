# ardis-viewer-portal

The page an employer opens when a healthcare professional shares a credential with
them. **No account, no signup, nothing persisted** — the recipient opens a link,
proves they hold the share code, and reads the credential. Closing the tab ends it.

It doubles as the browser return target for Stripe Checkout and Persona/Stripe
Identity, since those flows have to land somewhere on the web before handing
control back to the mobile app.

- **Repo:** `instruxi-io/ardis-viewer-portal` (branch `master`)
- **Stack:** plain ES modules + Vite 5. One runtime dependency (`ethers`, for
  signature recovery). No framework.
- **Deployed:** Cloudflare Pages — `ardis-viewer-portal.pages.dev`

The client is deliberately dumb and deliberately small. It never touches Storj,
never holds an access grant, and the decryption key never leaves the URL fragment.

---

## Quickstart

```bash
npm install
cp .env.example .env.local
npm run dev             # http://localhost:5173
```

```bash
npm run build
npm run preview
npm run selfcheck       # ARDIS1 envelope parity against the Flutter app
```

**Run `npm run selfcheck` after touching `src/envelope.js`.** That file is a
byte-compatible reimplementation of the Dart `ARDIS1` envelope in
`lib/src/core/envelope.dart`. If the two drift, shares silently stop decrypting,
and this script is the only thing guarding it.

### Environment

| Variable | Notes |
|---|---|
| `VITE_ARDIS_API_BASE` | ardis-ms origin, **without** `/api/v1/ardis` — the code appends it per call. Staging: `https://ardis-ms-ix.fly.dev` |
| `VITE_ENFORCER_BASE` | Gateway **with** `/api/v1/enforcer`. Used only by the OTP gate |

Both are baked in at **build** time, so changing a deployed value needs a rebuild
and redeploy, not an env edit.

`VITE_ENFORCER_BASE` must name the same gateway ardis-ms validates the resulting
JWT against, or the JWT is rejected server-side.

Full cross-repo reference:
[ardis-ms `docs/platform/ENVIRONMENT.md`](https://github.com/instruxi-io/ardis-ms-dev/blob/main/docs/platform/ENVIRONMENT.md).

---

## Deploying

Push to `master` → staging. GitHub Actions builds and runs
`wrangler pages deploy dist --project-name=ardis-viewer-portal`.

Build-time values come from the **GitHub Environment**, not from a committed file:
repo → Settings → Environments → `staging` → **Variables** (`VITE_ARDIS_API_BASE`,
`VITE_ENFORCER_BASE`). Cloudflare credentials are repo **secrets**
(`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`).

A `production` branch is wired in `.github/workflows/deploy.yml` for when a
production domain exists. It does not exist yet.

`_redirects` sends every path to `index.html` (SPA-style), which is what makes
`/view/{guid}` and the landing routes work on Pages.

---

## Routes

There is no router — `src/app.js` reads `window.location` directly.

| Path | Does |
|---|---|
| `/view/{guid}` | The credential viewer. Also accepts `?guid=` |
| `/` (or anything unmatched) | Share-code entry: type the 9-digit code to resolve a GUID |
| `/billing/success` | Subscription complete → `credpass://subscribe/complete` |
| `/billing/order-success` | Order paid → `credpass://order/complete` |
| `/billing/portal-return` | Billing portal done → `credpass://subscribe/complete` |
| `/billing/cancel` | Checkout cancelled, no charge → `credpass://subscribe/cancel` |
| `/kyc/return`, `/kyc/success` | Identity verified → `credpass://kyc/complete` |

Each landing route fires a `credpass://` deep link to hand control back to the app,
and renders a matching success/cancel state for a recipient who stays in the
browser. Note the scheme is still `credpass://` even though the Android
`applicationId` was renamed — they were not renamed together.

---

## How viewing a share works

```
1. GUID from /view/{guid}, or the 9-digit code → GET /public/share/code/{code}
2. probe GET /public/share/{guid}
     401 otp_required  → OTP gate     (DORMANT — never fires today)
     401 pin_required  → fall through
3. prompt for the 9-digit code
4. GET /public/share/{guid}  with  X-Share-Pin: {code}
5. decrypt the payload with K from the #k= URL fragment
6. recover the credential's signer and compare against the issuer key
7. fetch the display schema, render
```

### Two independent factors

| Factor | Where | Gates |
|---|---|---|
| Share key `K` | the `#k=` URL fragment | decrypting the bytes |
| 9-digit code | given to the recipient out of band | the server **releasing** the bytes |

Browsers never send the fragment to a server, so ardis-ms is a blind broker: it
holds ciphertext it has no key for. A leaked link alone is not enough; a leaked code
alone is not enough.

When the recipient arrives by typing the code rather than opening a link, those
digits are reused as the PIN instead of prompting twice.

`parseKeyFromHash()` in `src/envelope.js` reads `K`. If a link is missing its
fragment the viewer reports `missing_key` rather than a generic failure — that
usually means the link was copied from somewhere that strips fragments (some chat
clients do).

### Documents

Supporting documents stream through ardis-ms
(`GET /public/share/{guid}/documents?key=`), which uses its server-side grant. The
browser gets bytes, never a Storj URL. For encrypted shares the server streams the
ciphertext as-is and the viewer decrypts locally, then builds a blob URL using the
content type from the document metadata — the wire type is opaque
(`application/octet-stream`) by then.

### The OTP gate is built but switched off

ardis-ms hardcodes `RequireOTP: false`, so the `otp_required` branch never fires.
The full flow exists here — email → Enforcer OTP against the
`CredPass-Viewer-Portal` tenant → scoped JWT resent with the share request — and is
scaffolded so enabling it is a server-flag flip.

It is off pending two things:

1. **Viewer account auto-provisioning** in the `CredPass-Viewer-Portal` tenant. A
   recipient has no account, and the OTP flow needs one.
2. **A working email connection on that tenant.** Without it
   `POST /auth/login` returns `"Failed to send OTP email"` and the recipient is
   locked out entirely.

It was enabled once and reverted. Don't re-enable without both.

---

## Layout

```
index.html                 all markup, including the OTP/PIN/code dialogs
_redirects                 Cloudflare Pages SPA fallback
src/
  app.js                   routing, the share flow, OTP + PIN + code dialogs
  api.js                   ardis-ms client: share, documents, schema
  envelope.js              ARDIS1 decrypt + #k= fragment parsing
  verify.js                EIP-191 / secp256k1 signer recovery (ethers)
  render.js                credential, alerts, documents, landing pages
  styles.css
scripts/envelope-selfcheck.mjs   envelope parity guard — run it
```

The markup lives in `index.html` rather than being generated, which is why the
dialogs are present-but-hidden in the DOM.

---

## Recent fixes worth knowing

Two configuration bugs were fixed during handover cleanup:

- **`fetchSchema` called the wrong route.** It used
  `/public/display-schemas/...`, which ardis-ms renamed to
  `/public/credential-schemas/...`. Every schema fetch 404'd and returned `null`
  silently, so credentials rendered without their schema. Note the **Storj
  directory** is still called `display-schemas` — only the HTTP route changed.
- **`VITE_ENFORCER_BASE` was never read.** `app.js` derived the Enforcer base from
  the ardis-ms origin (`${API_BASE}/api/v1/enforcer`), which does not exist as a
  host. Latent only because the OTP gate is dormant — it would have broken the
  moment OTP was switched on.

Both fallback defaults also pointed at the Enforcer gateway instead of ardis-ms.

---

## Related

| Doc | Covers |
|---|---|
| [SHARING.md](https://github.com/instruxi-io/ardis-ms-dev/blob/main/docs/platform/SHARING.md) | All four sharing/fulfillment flows end to end |
| [ENVIRONMENT.md](https://github.com/instruxi-io/ardis-ms-dev/blob/main/docs/platform/ENVIRONMENT.md) | Every env var, all four repos |
| [app `docs/ENCRYPTION.md`](https://github.com/instruxi-io/ubuild-ardis/blob/main/docs/ENCRYPTION.md) | The ARDIS1 envelope this repo reimplements |
| [ardis-ms README](https://github.com/instruxi-io/ardis-ms-dev) | The API this portal calls |
