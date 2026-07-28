// Package connectionprofile applies named, campus-specific connection
// defaults without overriding explicit compatible values.
package connectionprofile

import (
	"fmt"
	"strings"

	"github.com/mythologyli/zju-connect/configs"
)

// Apply fills profile-owned defaults. Explicit non-default values remain
// available for campuses that deploy the same aTrust flow differently.
func Apply(conf *configs.Config) error {
	switch conf.Profile {
	case "", "default":
		return nil
	case "hitsz":
		conf.Protocol = "atrust"
		if conf.ServerAddress == "" || conf.ServerAddress == "rvpn.zju.edu.cn" || conf.ServerAddress == "vpn.zju.edu.cn" {
			conf.ServerAddress = "trust.hitsz.edu.cn"
		}
		if conf.LoginDomain == "" || conf.LoginDomain == "Radius" {
			conf.LoginDomain = "hitcas"
		}
		if conf.AuthType == "" {
			conf.AuthType = "auth/hitsz-sso"
		}
		if conf.DNSRelayBind == "" {
			conf.DNSRelayBind = "127.0.0.1:53535"
		}
		if conf.HITSZDNSServer == "" {
			conf.HITSZDNSServer = "10.248.98.30"
		}
		// These endpoints are consumed by the local Shadowrocket packet
		// tunnel and must not be exposed to the LAN.
		if conf.SocksBind == ":1080" {
			conf.SocksBind = "127.0.0.1:1080"
		}
		if conf.HTTPBind == ":1081" {
			conf.HTTPBind = "127.0.0.1:1081"
		}
		// Keep system routing as the default. Binding every authentication
		// socket with IP_BOUND_IF can change the IdP-visible path and conflicts
		// with packet-tunnel clients that use Fake IP. Callers can still opt in
		// to auto detection or select an explicit interface.
		// Shadowrocket sends only server-issued HITSZ rules to this proxy. A
		// direct fallback can be captured by Shadowrocket and form a loop.
		conf.ProxyAll = true
		conf.FakeIP = false
		conf.DNSHijack = false
		conf.NoSystemDNSMutation = true
		return nil
	default:
		return fmt.Errorf("HITSZ Connect: unsupported profile %q", conf.Profile)
	}
}

// ApplySecureConfig applies profile defaults and runtime migrations that are
// specific to encrypted profiles. HITSZ Connect 1.3.1 persisted its
// short-lived auto-detection default as true in every App-created profile.
// The secure-config workflow has no supported override flag or App setting for
// this field, so both legacy and current encrypted profiles use the reliable
// system-routing bootstrap. An explicit BindInterface remains authoritative.
func ApplySecureConfig(conf *configs.Config) error {
	if err := Apply(conf); err != nil {
		return err
	}
	if conf.Profile == "hitsz" {
		conf.AutoDetectInterface = false
	}
	return nil
}

// ValidateFileSourcePaths catches the common Go flag parsing mistake where a
// missing string value consumes the next flag name as if it were a filename.
// A real relative filename beginning with '-' remains expressible as './-x'.
func ValidateFileSourcePaths(conf configs.Config) error {
	for _, source := range []struct {
		name  string
		value string
	}{
		{name: "client-data-file", value: conf.ClientDataFile},
		{name: "mfa-otp-secret-file", value: conf.MFAOTPSecretFile},
		{name: "resource-file", value: conf.ResourceFile},
		{name: "shadowrocket-add-node-file", value: conf.ShadowrocketAddNodeFile},
		{name: "graph-code-file", value: conf.GraphCodeFile},
		{name: "cert-file", value: conf.CertFile},
	} {
		if strings.HasPrefix(strings.TrimSpace(source.value), "-") {
			return fmt.Errorf("HITSZ Connect: -%s value %q looks like another flag; provide the missing file path", source.name, source.value)
		}
	}
	return nil
}
