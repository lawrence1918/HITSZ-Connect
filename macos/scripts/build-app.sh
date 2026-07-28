#!/bin/sh
# Build a self-contained, ad-hoc-signed macOS application bundle.
#
# Usage:
#   ./macos/scripts/build-app.sh [path/to/prebuilt-hitsz-connect-darwin-arm64]
#
# With no argument, this script first builds the current repository source into
# a temporary staging path, so the bundled CLI always contains the matching
# `-app-bridge` implementation. The Go binary is only ever launched by the
# GUI with that argument.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
macos_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
project_dir=$(CDPATH= cd -- "$macos_dir/.." && pwd)
output_dir=${OUTPUT_DIR:-"$project_dir/dist/macos"}
app_bundle="$output_dir/HITSZ Connect.app"
build_dir="$macos_dir/.build/release"
icon_source="$macos_dir/Resources/AppIcon.icns"

mkdir -p "$output_dir"
staging_dir=$(mktemp -d "$output_dir/.hitsz-connect-cli.XXXXXX")
trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM

if [ "$#" -gt 0 ]; then
    cli_path=$1
    if [ ! -f "$cli_path" ]; then
        echo "HITSZ Connect CLI was not found: $cli_path" >&2
        exit 1
    fi
else
    cli_path="$staging_dir/hitsz-connect"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$cli_path" "$project_dir"
fi

if [ ! -f "$icon_source" ]; then
    echo "HITSZ Connect app icon was not found: $icon_source" >&2
    exit 1
fi

swift build --package-path "$macos_dir" -c release

rm -rf "$app_bundle"
mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources"
cp "$macos_dir/Info.plist" "$app_bundle/Contents/Info.plist"
cp "$icon_source" "$app_bundle/Contents/Resources/AppIcon.icns"
cp "$build_dir/HITSZConnect" "$app_bundle/Contents/MacOS/HITSZConnect"
cp "$cli_path" "$app_bundle/Contents/Resources/hitsz-connect"
chmod 755 "$app_bundle/Contents/MacOS/HITSZConnect" "$app_bundle/Contents/Resources/hitsz-connect"

# An ad-hoc signature is enough for local launch and preserves the nested
# executable's identity.  Distribution outside the local machine still needs
# the maintainer's Developer ID signing/notarization workflow.
codesign --force --sign - --deep "$app_bundle"
echo "Built $app_bundle"
