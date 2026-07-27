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

The UI polls macOS `scutil --nc` for Shadowrocket's real VPN state and byte
counters, and invokes the `shadowrocket://connect` / `shadowrocket://disconnect`
URL scheme only when the user chooses the corresponding action.
