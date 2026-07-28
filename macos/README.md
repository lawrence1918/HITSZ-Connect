# HITSZ Connect for macOS

This directory contains the native macOS front end for the HITSZ Connect CLI.
It is deliberately a small SwiftUI/SwiftPM project: the network protocol,
HITSZ authentication, and local proxy continue to live in the bundled
`hitsz-connect` executable.

## Build

On an Apple Silicon Mac with Xcode Command Line Tools:

```sh
./macos/scripts/build-app.sh
open "dist/macos/HITSZ Connect.app"
```

Pass a CLI path as the first argument when it is not in
`dist/hitsz/hitsz-connect-darwin-arm64`. The script produces an ad-hoc signed
bundle for local use. Developer ID signing and notarization remain a release
step for public distribution.

## Profiles and secrets

Profiles are stored only in `~/Documents/hitsz-connect/` with the `.hcenc`
extension. The file is an AES-256-GCM encrypted JSON envelope. Each profile's
random key is held in the macOS Keychain under service
`com.heheyizhi.hitsz-connect.config-key.v1`; credentials, OTP seeds, and saved
aTrust client data are never written to a plaintext TOML file or process
arguments.

The encrypted envelope is intentionally shared with the command-line secure
config implementation:

```text
magic       hitsz-connect-config
version     1
id          profile UUID
nonce       standard-base64 12-byte GCM nonce
ciphertext  standard-base64 (GCM ciphertext followed by its 16-byte tag)
AAD         com.heheyizhi.hitsz-connect.config.v1:<profile UUID>
```

The key is device-local by design. Copying a `.hcenc` file to a different Mac
does not copy its Keychain key, so it cannot be opened there. Create a new
profile on the destination device instead.

The `config` object is a lossless flat JSON map matching the CLI's encrypted
profile format. The editor exposes the HITSZ-relevant settings, while fields
introduced by a newer CLI are preserved verbatim on read/save. Runtime-only
MFA codes, tickets, debug identities, and file-source paths are stripped.

## CLI bridge

The app starts the bundled executable only as `hitsz-connect -app-bridge`.
It sends newline-delimited JSON through stdin and receives newline-delimited
status JSON from stdout. The first command uses `type: "connect"` with the
decrypted `config` object and optional base64 `clientData`; no password or OTP
secret is placed in argv, an environment variable, or a temporary plaintext
file. It accepts bridge events `phase`, `ready`, `status`, `clientData`,
`mfaRequired`, `error`, and `stopped`.

The UI discovers Shadowrocket's NetworkExtension service UUID with
`scutil --nc`, cross-checks the active Shadowrocket-labelled `utun`, and reads
its byte counters through `getifaddrs`. It controls the VPN primarily with
`scutil --nc start/stop <UUID>`. If a URL-scheme-started tunnel has a running
utun while that service still says Disconnected, the App falls back to
`open -g -j shadowrocket://...`, matching the CLI without opening or
foregrounding the Shadowrocket window.

When an existing Shadowrocket tunnel is active, the App pauses it before
aTrust bootstrap so HITSZ authentication cannot be routed into the not-yet-
available local SOCKS listener. The bridge keeps system routing by default;
forcing every CAS/IdP socket onto an auto-detected interface can change the
IdP-visible path and conflict with Fake-IP VPNs. Shadowrocket is restored or
started only after the bridge emits `ready`. Cancellation, authentication
failure, and application termination retain a restore lease for any tunnel
that was active before the attempt.

If the HITSZ IdP requests its slider CAPTCHA, the bundled bridge opens a
tokenized localhost page in the default browser. The puzzle is fetched and
verified with the bridge's own IdP cookie session, then the App continues the
credential flow. Opening the public IdP page directly can reuse unrelated
browser CAS cookies and does not satisfy this challenge.
