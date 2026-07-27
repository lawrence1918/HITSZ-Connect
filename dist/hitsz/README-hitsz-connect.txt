HITSZ Connect / aTrust build
=============================

This is the HITSZ-specific fork of zju-connect. It supports HITSZ unified
authentication, HITSZ App/SMS/OTP MFA, the HITSZ DNS relay, and macOS
Shadowrocket split routing. It is not an official HITSZ client.

OTP MFA (recommended secret handling)
-------------------------------------

Save a single Base32 seed or otpauth://totp/... URI in a file and restrict it
to the current user:

  chmod 600 /path/to/hitsz-otp.secret

First start the client and generate the account-specific Shadowrocket rules:

./hitsz-connect-darwin-arm64 \
  -profile hitsz \
  -username '<phone-number-or-student-id>' \
  -password '<HITSZ-password>' \
  -mfa-method otp \
  -mfa-otp-secret-file /path/to/hitsz-otp.secret \
  -client-data-file ./hitsz-client-data.json \
  -shadowrocket off \
  -shadowrocket-config-fragment ./hitsz-shadowrocket.conf

Merge the generated [Proxy], [Rule], and [Host] entries into the active
Shadowrocket configuration before generic private-IP DIRECT and FINAL rules.
Then start the same command with -shadowrocket connect, or connect
Shadowrocket manually.

SMS / App MFA
-------------

Use `-mfa-method sms` or `-mfa-method app` instead. The client prompts for the
one-time code in the terminal. Do not place MFA codes, passwords, or OTP seeds
in shell history, Git, or issue reports.

DNS / Shadowrocket
------------------

The HITSZ profile keeps global macOS DNS unchanged. It starts a loopback DNS
relay on 127.0.0.1:53535 for hitsz.edu.cn and its subdomains, forwarding those
queries through aTrust to 10.248.98.30:53/TCP. The local SOCKS5 proxy listens
on 127.0.0.1:1080. Dynamic IP rules are restricted to 10.248.0.0/16 through
10.250.0.0/16 to avoid capturing a local LAN.

Do not add 10.248.98.30 to an excluded route, and do not redirect the whole
10.0.0.0/8 range to the local SOCKS proxy.

Security
--------

The client-data file contains login state and must be treated as a credential.
Keep it, OTP seed files, and any generated account-specific config out of Git.
