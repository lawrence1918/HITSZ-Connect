HITSZ Connect 1.3.8 / CLI 1.3.8-hitsz.1
=========================================

This is the HITSZ-specific fork of zju-connect for macOS 13+ on Apple
Silicon. It supports HITSZ unified authentication, App/SMS/OTP MFA, the
HITSZ DNS relay, and Shadowrocket split routing. It is not an official HITSZ
client.

Recommended: macOS App and encrypted profiles
----------------------------------------------

The recommended client is ../macos/HITSZ Connect.app. From the repository
root, install and open it with:

  ditto "dist/macos/HITSZ Connect.app" "/Applications/HITSZ Connect.app"
  open "/Applications/HITSZ Connect.app"

Before connecting, merge
shadowrocket/Shadowrocket-HITSZ-DNS-relay-fragment.conf into the active
Shadowrocket configuration. Put its rules before generic private-IP DIRECT
and FINAL rules. The App can connect or disconnect Shadowrocket, but does not
import, merge, or activate its configuration.

Create a profile in the App and enter the username, password, and MFA method.
Profiles are stored as ~/Documents/hitsz-connect/*.hcenc. Their contents are
encrypted with AES-256-GCM, and each profile's key is stored in the current
Mac user's Keychain. Copying only the .hcenc file to another Mac does not copy
the key; create a new profile on the destination device.

Encrypted-profile CLI
---------------------

The App's encrypted profiles can also be used by this CLI:

  ./hitsz-connect-darwin-arm64 -list-secure-configs
  ./hitsz-connect-darwin-arm64 -secure-config '<profile UUID>'

Each secure-config flag must be used alone. Do not combine it with username,
password, or other runtime flags; edit the profile in the App instead. This
workflow requires a CGO_ENABLED=1 macOS build because it uses the Keychain.

Plaintext CLI compatibility mode
--------------------------------

Direct flags remain available for compatibility and debugging, for example:

  ./hitsz-connect-darwin-arm64 \
    -profile hitsz \
    -username '<phone-number-or-student-id>' \
    -password '<HITSZ-password>' \
    -mfa-method otp \
    -mfa-otp-secret-file /path/to/hitsz-otp.secret \
    -client-data-file ./hitsz-client-data.json \
    -shadowrocket connect

This is not the recommended way to store credentials. A password in argv may
appear in shell history or process listings. OTP seed files, client-data
files, TOML configs, and generated account-specific rules are plaintext and
must be treated as credentials. Restrict their permissions and never commit,
sync, or paste them into issue reports. Use -mfa-method sms or app when needed;
the CLI prompts for the one-time code.

DNS / Shadowrocket
------------------

The HITSZ profile keeps global macOS DNS unchanged. It starts a loopback DNS
relay on 127.0.0.1:53535 for hitsz.edu.cn and its subdomains, forwarding those
queries through aTrust to 10.248.98.30:53/TCP. The local SOCKS5 proxy listens
on 127.0.0.1:1080. Dynamic IP rules are restricted to 10.248.0.0/16 through
10.250.0.0/16 to avoid capturing a local LAN.

Do not add 10.248.98.30 to an excluded route, do not redirect all of
10.0.0.0/8 to the local SOCKS proxy, and do not use the legacy/ full config
at the same time as the built-in HITSZ relay.
