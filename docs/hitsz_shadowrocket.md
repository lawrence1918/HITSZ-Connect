# HITSZ Connect aTrust + Shadowrocket

The HITSZ Connect profile connects to `trust.hitsz.edu.cn`, signs in through the HITSZ
unified-authentication CAS provider, starts a loopback SOCKS5 endpoint on
`127.0.0.1:1080`, and starts a DNS relay on `127.0.0.1:53535`. Only
`hitsz.edu.cn` and its subdomains are accepted by that relay; they are sent
over the aTrust connection to `10.248.98.30` using TCP.

Example (the MFA code is prompted interactively):

```sh
./hitsz-connect -profile hitsz -username '<phone-or-student-id>' -password '<password>' \
  -mfa-method app -client-data-file hitsz-client-data.json \
  -shadowrocket connect -shadowrocket-config-fragment shadowrocket-hitsz.conf
```

Use `-mfa-method sms` for an SMS code. `-mfa-code` is intended for controlled
non-interactive use; it should not be placed in shell history. HITSZ cookies
and aTrust state are saved in `client_data_file` with mode `0600`.

HITSZ security-token OTP is also supported with `-mfa-method otp`. Give the
client a bare Base32 seed or an `otpauth://totp/...` URI with
`-mfa-otp-secret-file`; the file must be a regular file readable only by its
owner. The client generates the SHA-1, 30-second, six-digit code locally and
submits it as `otpCode`. `-mfa-otp-secret` is available for automation but is
less safe because command-line arguments may be visible to other processes.

Merge the generated fragment section-by-section into the active Shadowrocket
configuration; do not append its repeated section headers as a second complete
configuration. It uses `always-real-ip = *`, adds `HITSZ-aTrust = socks5,
127.0.0.1, 1080`, and routes the server-issued HITSZ/licensed-resource domains
plus direct-IP campus resources to that local proxy. Direct-IP rules are
strictly limited to `10.248.0.0/16` through `10.250.0.0/16`; other private
server resources are deliberately omitted to avoid hijacking a local LAN.
Place those rules before generic private-IP `DIRECT` and `FINAL` rules. The
HITSZ local proxy fails closed outside its aTrust ACL, avoiding a direct-dial
loop through Shadowrocket. Do not add `10.248.98.30` to Shadowrocket's
excluded routes and do not route the entire `10.0.0.0/8` range to the local
proxy.

For an AnyTLS node, put exactly one `anytls://` URI in a permission-restricted
file and pass `-shadowrocket-add-node-file <file>`. HITSZ Connect validates and
hands it to Shadowrocket; Shadowrocket performs the actual AnyTLS transport.
