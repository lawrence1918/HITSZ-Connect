// Package connectionprofile applies named, campus-specific connection
// defaults without overriding explicit compatible values.
package connectionprofile

import (
	"fmt"

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
		// Authentication must reach the IdP over the physical underlay even
		// when a packet-tunnel proxy is already active.
		if conf.BindInterface == "" {
			conf.AutoDetectInterface = true
		}
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
