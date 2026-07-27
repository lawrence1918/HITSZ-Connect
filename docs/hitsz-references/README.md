# HITSZ browser-capture reference (sanitized)

This directory records only the **shape** and ordering of the HITSZ/aTrust
browser flows used while maintaining `hitsz-connect` (the HITSZ fork of
`zju-connect`). It is deliberately not a
replay fixture. The original exports remain outside this repository and must
never be copied here.

## Source manifest

| Capture | Original path | Size | SHA-256 | Intended use |
| --- | --- | ---: | --- | --- |
| `atrust.txt` | `/Users/heheyizhi/Downloads/atrust.txt` | 758,922 bytes | `bbaf4f8c968233c518a449481532409e7f41bc5f07df2834d33ba6633a7f5553` | Full browser CAS and secondary-authentication sequence. |
| `aTrust2.txt` | `/Users/heheyizhi/Downloads/aTrust2.txt` | 6,430 bytes | `01cdd21e98480a7b58776870b98cd734ad86297a2e68291f4cbdbedfe516925a` | Narrow post-login `authCheck` reference. |
| `atrust3.txt` | `/Users/heheyizhi/Downloads/atrust3.txt` | 1,339,747 bytes | `70b41cab657f0d07f3bb6b86708f16e03269675ae2883992205ca4d1f4f0050c` | Browser portal lifecycle, CAS callback, and official local-agent integration. |

The hashes identify the supplied source files only; they are not credentials
and do not make the captures safe to publish.

## `atrust.txt`: CAS plus secondary authentication

Purpose: establish the browser-side order for the HITSZ unified-authentication
and aTrust handoff.

Observed endpoint shape, in order:

1. aTrust `GET /passport/v1/public/casLogin` with browser/CAS query keys;
   redirect to the IdP `GET /authserver/login` with a `service` key.
2. IdP login document and browser-support requests, including tenant,
   fingerprint, and captcha/QR-related endpoints.
3. `POST /authserver/login` with the same `service` key; redirect to
   `GET /authserver/reAuthCheck/reAuthLoginView.do`.
4. Secondary-authentication preparation: `POST /authserver/systemTime`,
   `POST /authserver/reAuthCheck/changeReAuthType.do`, and, for methods that
   require it, `POST /authserver/dynamicCode/getDynamicCodeByReauth.do`.
5. `POST /authserver/reAuthCheck/reAuthSubmit.do` as an AJAX-shaped request.
   The successful response is a small JSON acknowledgement, rather than the
   CAS callback itself.
6. A follow-up `GET /authserver/login` with the original `service` key;
   redirect to aTrust `GET /passport/v1/auth/cas` with CAS callback query
   keys.
7. aTrust CAS callback redirect to `/portal/shortcut.html`, followed by
   browser-shaped `/passport/v1/auth/authCheck`.

Key implementation conclusions:

- The final IdP callback is obtained by revisiting the IdP login endpoint
  after secondary-authentication success; it is not the body of the submit
  response.
- The `service` URL can express the default HTTPS port while the callback
  authority omits it. Compare HTTPS authorities with default-port
  normalization.
- The secondary submit request uses the browser AJAX convention; request
  field values, codes, cookies, and callback query values are intentionally
  absent from this document.

## `aTrust2.txt`: post-portal `authCheck`

Purpose: isolate the aTrust request immediately used to determine the next
authentication step after portal state exists.

Observed endpoint shape:

1. `GET /passport/v1/auth/authCheck` with browser identity query keys
   (`clientType`, `platform`, and language).
2. JSON response describing the next authentication state.

Key implementation conclusion: HITSZ browser SSO must use its browser-shaped
client identity for `authCheck`; it must not silently inherit the legacy
desktop-client parameters used by unrelated aTrust tenants.

## `atrust3.txt`: portal lifecycle and local official-client boundary

Purpose: distinguish remote aTrust calls from requests served by the official
local aTrust agent.

Relevant endpoint shape after a successful CAS callback:

1. aTrust `GET /passport/v1/public/authConfig` with browser identity plus
   `mod` and `needTicket` query keys.
2. Browser-to-local-agent requests under `https://localhost.sangfor.com.cn`
   on the official agent port, including detection, initialization,
   anti-MITM checking, and `/v1/service/reportEnvBeforeLogin`.
3. aTrust `GET /passport/v1/auth/authCheck` with browser identity query keys.
4. Further local-agent and portal resource requests may follow.

Key implementation conclusions:

- `reportEnvBeforeLogin` is a **local official-client API**, not a remote
  `trust.hitsz.edu.cn` endpoint. `zju-connect` must never forward its
  local-agent payload to the gateway.
- For standalone operation, the safe remote fallback is: refresh
  `authConfig` after CAS, use browser identity for the existing aTrust
  environment transition, and continue to `authCheck` even when that
  best-effort environment report fails.
- The post-CAS `authConfig` refresh supplies the current CSRF/session state;
  do not reuse values obtained before the CAS handoff.

## Hard red lines

- Do not add the raw `atrust*.txt` files, screenshots, decoded Burp bodies,
  HAR files, or packet captures to this repository.
- Do not record or log cookies, authorization headers, session identifiers,
  callback parameters, account identifiers, phone numbers, passwords,
  verification codes, OTP secrets, or any request/response value.
- Do not include copied request headers or JSON bodies, even if individual
  fields appear harmless. This reference may describe endpoint paths, HTTP
  methods, query **key names**, response classes, and ordering only.
- Use synthetic fixtures for tests. Test values must be obviously artificial
  and must never be derived from a capture.
- If the source captures need re-verification, inspect them locally and update
  only this manifest metadata and the value-free behavioral conclusions.
