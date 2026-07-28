package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/internal/connectionprofile"
)

var CommitID string
var appBridge bool
var secureConfigID string
var listSecureConfigs bool

const hitszConnectVersion = "1.3.9-hitsz.1"

func getTOMLVal[T int | uint64 | string | bool](valPointer *T, defaultVal T) T {
	if valPointer == nil {
		return defaultVal
	} else {
		return *valPointer
	}
}

func parseTOMLConfig(configFile string, conf *configs.Config) error {
	var confTOML configs.ConfigTOML

	_, err := toml.DecodeFile(configFile, &confTOML)
	if err != nil {
		return errors.New("ZJU Connect: error parsing the config file")
	}

	conf.Protocol = getTOMLVal(confTOML.Protocol, "easyconnect")
	conf.ServerAddress = getTOMLVal(confTOML.ServerAddress, "rvpn.zju.edu.cn")
	conf.ServerPort = getTOMLVal(confTOML.ServerPort, 443)
	conf.Username = getTOMLVal(confTOML.Username, "")
	conf.Password = getTOMLVal(confTOML.Password, "")
	conf.TOTPSecret = getTOMLVal(confTOML.TOTPSecret, "")
	conf.CertFile = getTOMLVal(confTOML.CertFile, "")
	conf.CertPassword = getTOMLVal(confTOML.CertPassword, "")
	conf.DisableServerConfig = getTOMLVal(confTOML.DisableServerConfig, false)
	conf.SkipDomainResource = getTOMLVal(confTOML.SkipDomainResource, false)
	conf.DisableZJUConfig = getTOMLVal(confTOML.DisableZJUConfig, false)
	conf.DisableRemoteDNS = getTOMLVal(confTOML.DisableRemoteDNS, false)
	conf.DisableMultiLine = getTOMLVal(confTOML.DisableMultiLine, false)
	conf.ProxyAll = getTOMLVal(confTOML.ProxyAll, false)
	conf.SocksBind = getTOMLVal(confTOML.SocksBind, ":1080")
	conf.SocksUser = getTOMLVal(confTOML.SocksUser, "")
	conf.SocksPasswd = getTOMLVal(confTOML.SocksPasswd, "")
	conf.HTTPBind = getTOMLVal(confTOML.HTTPBind, ":1081")
	conf.ShadowsocksURL = getTOMLVal(confTOML.ShadowsocksURL, "")
	conf.DialDirectProxy = getTOMLVal(confTOML.DialDirectProxy, "")
	conf.TCPTunnelMode = getTOMLVal(confTOML.TCPTunnelMode, false)
	conf.TUNMode = getTOMLVal(confTOML.TUNMode, false)
	conf.AddRoute = getTOMLVal(confTOML.AddRoute, false)
	conf.DNSTTL = getTOMLVal(confTOML.DNSTTL, uint64(3600))
	conf.DebugDump = getTOMLVal(confTOML.DebugDump, false)
	conf.DisableKeepAlive = getTOMLVal(confTOML.DisableKeepAlive, false)
	conf.KeepAliveURL = getTOMLVal(confTOML.KeepAliveURL, "")
	conf.RemoteDNSServer = getTOMLVal(confTOML.RemoteDNSServer, "auto")
	conf.SecondaryDNSServer = getTOMLVal(confTOML.SecondaryDNSServer, "114.114.114.114")
	conf.DNSServerBind = getTOMLVal(confTOML.DNSServerBind, "")
	conf.DNSHijack = getTOMLVal(confTOML.DNSHijack, false)
	conf.FakeIP = getTOMLVal(confTOML.FakeIP, false)
	conf.GraphCodeFile = getTOMLVal(confTOML.GraphCodeFile, "")
	conf.BindInterface = getTOMLVal(confTOML.BindInterface, "")
	conf.AutoDetectInterface = getTOMLVal(confTOML.AutoDetectInterface, false)
	conf.Profile = getTOMLVal(confTOML.Profile, "")
	conf.NoSystemDNSMutation = getTOMLVal(confTOML.NoSystemDNSMutation, false)
	conf.MFAMethod = getTOMLVal(confTOML.MFAMethod, "")
	conf.MFACode = getTOMLVal(confTOML.MFACode, "")
	conf.MFAOTPSecret = getTOMLVal(confTOML.MFAOTPSecret, "")
	conf.MFAOTPSecretFile = getTOMLVal(confTOML.MFAOTPSecretFile, "")
	conf.NonInteractive = getTOMLVal(confTOML.NonInteractive, false)
	conf.RememberSSO = getTOMLVal(confTOML.RememberSSO, true)
	conf.RememberMFA = getTOMLVal(confTOML.RememberMFA, true)
	conf.DNSRelayBind = getTOMLVal(confTOML.DNSRelayBind, "")
	conf.HITSZDNSServer = getTOMLVal(confTOML.HITSZDNSServer, "10.248.98.30")
	conf.Shadowrocket = getTOMLVal(confTOML.Shadowrocket, "off")
	conf.ShadowrocketUpdateSubs = getTOMLVal(confTOML.ShadowrocketUpdateSubs, false)
	conf.ShadowrocketAddNodeFile = getTOMLVal(confTOML.ShadowrocketAddNodeFile, "")
	conf.ShadowrocketDisconnectOnExit = getTOMLVal(confTOML.ShadowrocketDisconnectOnExit, false)
	conf.ShadowrocketConfigFragment = getTOMLVal(confTOML.ShadowrocketConfigFragment, "")
	conf.AuthType = getTOMLVal(confTOML.AuthType, "")
	conf.Phone = getTOMLVal(confTOML.Phone, "")
	conf.LoginDomain = getTOMLVal(confTOML.LoginDomain, "Radius")
	conf.ClientDataFile = getTOMLVal(confTOML.ClientDataFile, "")
	conf.CasTicket = getTOMLVal(confTOML.CasTicket, "")
	conf.OAuth2Code = getTOMLVal(confTOML.OAuth2Code, "")
	conf.SID = getTOMLVal(confTOML.SID, "")
	conf.DeviceID = getTOMLVal(confTOML.DeviceID, "")
	conf.SignKey = getTOMLVal(confTOML.SignKey, "")
	conf.ResourceFile = getTOMLVal(confTOML.ResourceFile, "")
	conf.UpdateBestNodesInterval = getTOMLVal(confTOML.UpdateBestNodesInterval, 300)
	conf.SkipTCPTunnelWait = getTOMLVal(confTOML.SkipTCPTunnelWait, false)

	for _, singlePortForwarding := range confTOML.PortForwarding {
		if singlePortForwarding.NetworkType == nil {
			return errors.New("ZJU Connect: network type is not set")
		}

		if singlePortForwarding.BindAddress == nil {
			return errors.New("ZJU Connect: bind address is not set")
		}

		if singlePortForwarding.RemoteAddress == nil {
			return errors.New("ZJU Connect: remote address is not set")
		}

		conf.PortForwardingList = append(conf.PortForwardingList, configs.SinglePortForwarding{
			NetworkType:   *singlePortForwarding.NetworkType,
			BindAddress:   *singlePortForwarding.BindAddress,
			RemoteAddress: *singlePortForwarding.RemoteAddress,
		})
	}

	for _, singleCustomDns := range confTOML.CustomDNS {
		if singleCustomDns.HostName == nil {
			return errors.New("ZJU Connect: host name is not set")
		}

		if singleCustomDns.IP == nil {
			fmt.Println("ZJU Connect: IP is not set")
			return errors.New("ZJU Connect: IP is not set")
		}

		conf.CustomDNSList = append(conf.CustomDNSList, configs.SingleCustomDNS{
			HostName: *singleCustomDns.HostName,
			IP:       *singleCustomDns.IP,
		})
	}

	for _, singleCustomProxyDomain := range confTOML.CustomProxyDomain {
		var domainRegex = regexp.MustCompile(`^[a-zA-Z\d-]+(\.[a-zA-Z\d-]+)*\.[a-zA-Z]{2,}$`)
		if !domainRegex.MatchString(singleCustomProxyDomain) {
			fmt.Printf("ZJU Connect: %s is not a valid domain\n", singleCustomProxyDomain)
			return fmt.Errorf("ZJU Connect: %s is not a valid domain", singleCustomProxyDomain)
		}
		conf.CustomProxyDomain = append(conf.CustomProxyDomain, singleCustomProxyDomain)
	}

	return nil
}

func applyProfile(conf *configs.Config) error {
	return connectionprofile.Apply(conf)
}

func applySecureConfigProfile(conf *configs.Config) error {
	return connectionprofile.ApplySecureConfig(conf)
}

func validateFileSourcePaths(conf configs.Config) error {
	return connectionprofile.ValidateFileSourcePaths(conf)
}

func init() {
	configFile, tcpPortForwarding, udpPortForwarding, customDns, customProxyDomain := "", "", "", "", ""
	showVersion := false
	atrustAuthInfo := false
	atrustTrustDevice := false
	atrustUntrustDevice := false

	flag.StringVar(&conf.Protocol, "protocol", "easyconnect", "Protocol (easyconnect, atrust)")
	flag.StringVar(&conf.ServerAddress, "server", "rvpn.zju.edu.cn", "EasyConnect/aTrust server address")
	flag.IntVar(&conf.ServerPort, "port", 443, "EasyConnect/aTrust port address")
	flag.StringVar(&conf.Username, "username", "", "Your username")
	flag.StringVar(&conf.Password, "password", "", "Your password")
	flag.StringVar(&conf.TOTPSecret, "totp-secret", "", "TOTP secret")
	flag.StringVar(&conf.CertFile, "cert-file", "", "Client certificate p12 file path for certificate login")
	flag.StringVar(&conf.CertPassword, "cert-password", "", "Client certificate password")
	flag.BoolVar(&conf.DisableServerConfig, "disable-server-config", false, "Don't parse server config")
	flag.BoolVar(&conf.SkipDomainResource, "skip-domain-resource", false, "Don't use server domain resource to decide whether to use RVPN.")
	flag.BoolVar(&conf.DisableZJUConfig, "disable-zju-config", false, "Don't use ZJU config (for easyconnect protocol only)")
	flag.BoolVar(&conf.DisableRemoteDNS, "disable-zju-dns", false, "Use local DNS instead of remote DNS") // TODO: rename to disable-remote-dns
	flag.BoolVar(&conf.DisableMultiLine, "disable-multi-line", false, "Disable multi line auto select")
	flag.BoolVar(&conf.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.StringVar(&conf.SocksBind, "socks-bind", ":1080", "The address SOCKS5 server listens on (e.g. 127.0.0.1:1080)")
	flag.StringVar(&conf.SocksUser, "socks-user", "", "SOCKS5 username, default is don't use auth")
	flag.StringVar(&conf.SocksPasswd, "socks-passwd", "", "SOCKS5 password, default is don't use auth")
	flag.StringVar(&conf.HTTPBind, "http-bind", ":1081", "The address HTTP server listens on (e.g. 127.0.0.1:1081)")
	flag.StringVar(&conf.ShadowsocksURL, "shadowsocks-url", "", "The address Shadowsocks server listens on (e.g. ss://method:password@host:port)")
	flag.StringVar(&conf.DialDirectProxy, "dial-direct-proxy", "", "Dial with proxy when the connection doesn't match RVPN rules (e.g. http://127.0.0.1:7890)")
	flag.BoolVar(&conf.TCPTunnelMode, "tcp-tunnel-mode", false, "Use TCP tunnel only and disable L3 tunnel, only works with atrust protocol")
	flag.BoolVar(&conf.TUNMode, "tun-mode", false, "Enable TUN mode (experimental)")
	flag.BoolVar(&conf.AddRoute, "add-route", false, "Add route from rules for TUN interface")
	flag.Uint64Var(&conf.DNSTTL, "dns-ttl", 3600, "DNS record time to live, unit is second")
	flag.BoolVar(&conf.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.BoolVar(&conf.DisableKeepAlive, "disable-keep-alive", false, "Disable keep alive")
	flag.StringVar(&conf.KeepAliveURL, "keep-alive-url", "", "Keep alive URL, default is empty (use DNS keep alive)")
	flag.StringVar(&conf.RemoteDNSServer, "zju-dns-server", "auto", "Remote DNS server address. Set to 'auto' to use remote DNS server provided by server") // TODO: rename to remote-dns-server
	flag.StringVar(&conf.SecondaryDNSServer, "secondary-dns-server", "114.114.114.114", "Secondary DNS server address. Leave empty to use system default DNS server")
	flag.StringVar(&conf.DNSServerBind, "dns-server-bind", "", "The address DNS server listens on (e.g. 127.0.0.1:53)")
	flag.BoolVar(&conf.DNSHijack, "dns-hijack", false, "Hijack all dns query to ZJU Connect. False by default.")
	flag.BoolVar(&conf.FakeIP, "fake-ip", false, "Enable Fake IP for DNS hijack")
	flag.StringVar(&conf.GraphCodeFile, "graph-code-file", "", "Graph Check Code File")
	flag.StringVar(&conf.BindInterface, "bind-interface", "", "Bind VPN underlay connections to this network interface (takes precedence over auto detection)")
	flag.BoolVar(&conf.AutoDetectInterface, "auto-detect-interface", false, "Automatically detect and bind the VPN underlay interface")
	flag.StringVar(&conf.Profile, "profile", "", "Configuration profile (hitsz)")
	flag.BoolVar(&conf.NoSystemDNSMutation, "no-system-dns-mutation", false, "Never change macOS system DNS settings")
	flag.StringVar(&conf.MFAMethod, "mfa-method", "", "HITSZ MFA method: app, sms, or otp")
	flag.StringVar(&conf.MFACode, "mfa-code", "", "HITSZ MFA verification code (prompt if omitted)")
	flag.StringVar(&conf.MFAOTPSecret, "mfa-otp-secret", "", "HITSZ OTP/TOTP Base32 secret or otpauth:// URI (not recommended on command line; never persisted)")
	flag.StringVar(&conf.MFAOTPSecretFile, "mfa-otp-secret-file", "", "File containing one HITSZ OTP/TOTP secret (must not be group/world-readable)")
	flag.BoolVar(&conf.NonInteractive, "non-interactive", false, "Fail instead of prompting for HITSZ MFA input")
	flag.BoolVar(&conf.RememberSSO, "remember-sso", true, "Remember HITSZ unified-authentication session")
	flag.BoolVar(&conf.RememberMFA, "remember-mfa", true, "Request temporary HITSZ MFA remember state")
	flag.StringVar(&conf.DNSRelayBind, "dns-relay-bind", "", "HITSZ DNS relay bind address (default 127.0.0.1:53535 for hitsz profile)")
	flag.StringVar(&conf.HITSZDNSServer, "hitsz-dns-server", "10.248.98.30", "HITSZ DNS server used by the relay")
	flag.StringVar(&conf.Shadowrocket, "shadowrocket", "off", "Shadowrocket action: off, open, or connect")
	flag.BoolVar(&conf.ShadowrocketUpdateSubs, "shadowrocket-update-subs", false, "Ask Shadowrocket to update subscriptions")
	flag.StringVar(&conf.ShadowrocketAddNodeFile, "shadowrocket-add-node-file", "", "File containing one anytls:// node URI to import into Shadowrocket")
	flag.BoolVar(&conf.ShadowrocketDisconnectOnExit, "shadowrocket-disconnect-on-exit", false, "Disconnect Shadowrocket when zju-connect exits")
	flag.StringVar(&conf.ShadowrocketConfigFragment, "shadowrocket-config-fragment", "", "Write a compatible Shadowrocket config fragment to this file")
	flag.StringVar(&conf.TwfID, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.StringVar(&conf.AuthType, "auth-type", "", "aTrust authentication type (auth/psw, auth/cas, auth/hitsz-sso, auth/httpsOauth2, auth/smsCheckCode)")
	flag.StringVar(&conf.Phone, "phone", "", "Phone number with country code for aTrust SMS check code login (e.g. 852-114514)")
	flag.StringVar(&conf.LoginDomain, "login-domain", "Radius", "aTrust login domain")
	flag.StringVar(&conf.ClientDataFile, "client-data-file", "", "aTrust Client Data File")
	flag.StringVar(&conf.CasTicket, "cas-ticket", "", "aTrust CAS Ticket (optional, interactive mode if not set)")
	flag.StringVar(&conf.OAuth2Code, "oauth2-code", "", "aTrust OAuth2 code (optional, interactive mode if not set)")
	flag.StringVar(&conf.SID, "sid", "", "aTrust SID (mostly for debug usage)")
	flag.StringVar(&conf.DeviceID, "device-id", "", "aTrust Device ID (mostly for debug usage)")
	flag.StringVar(&conf.SignKey, "sign-key", "", "aTrust Sign Key (mostly for debug usage)")
	flag.StringVar(&conf.ResourceFile, "resource-file", "", "aTrust Resource File (mostly for debug usage)")
	flag.IntVar(&conf.UpdateBestNodesInterval, "update-best-nodes-interval", 300, "Interval to update best nodes in seconds. Set to 0 to disable")
	flag.BoolVar(&conf.SkipTCPTunnelWait, "skip-tcp-tunnel-wait", false, "Don't wait for aTrust TCP tunnel connection status")
	flag.StringVar(&tcpPortForwarding, "tcp-port-forwarding", "", "TCP port forwarding (e.g. 0.0.0.0:9898-10.10.98.98:80,127.0.0.1:9899-10.10.98.98:80)")
	flag.StringVar(&udpPortForwarding, "udp-port-forwarding", "", "UDP port forwarding (e.g. 127.0.0.1:53-10.10.0.21:53)")
	flag.StringVar(&customDns, "custom-dns", "", "Custom set dns lookup (e.g. www.cc98.org:10.10.98.98,appservice.zju.edu.cn:10.203.8.198)")
	flag.StringVar(&customProxyDomain, "custom-proxy-domain", "", "Custom set domains which force use RVPN proxy  (e.g. science.org, nature.com)")
	flag.StringVar(&configFile, "config", "", "Config file")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&atrustAuthInfo, "auth-info", false, "Fetch aTrust authentication information, but not login")
	flag.BoolVar(&atrustTrustDevice, "trust-device", false, "Trust the current device for aTrust with client data, but not connect")
	flag.BoolVar(&atrustUntrustDevice, "untrust-device", false, "Untrust the current device for aTrust with client data, but not connect")
	flag.BoolVar(&appBridge, "app-bridge", false, "Read app commands from stdin and emit newline-delimited JSON events on stdout")
	flag.StringVar(&secureConfigID, "secure-config", "", "Load encrypted connection UUID from ~/Documents/hitsz-connect")
	flag.BoolVar(&listSecureConfigs, "list-secure-configs", false, "List encrypted connections in ~/Documents/hitsz-connect")

	flag.Parse()
	if appBridge {
		// The app supplies the complete runtime configuration over stdin. Do not
		// validate defaults or inspect secret-bearing command-line arguments.
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "app-bridge" {
				fmt.Fprintf(os.Stderr, "HITSZ Connect: -app-bridge does not accept -%s; send configuration over stdin\n", f.Name)
				os.Exit(2)
			}
		})
		return
	}
	if secureConfigID != "" || listSecureConfigs {
		if secureConfigID != "" && listSecureConfigs {
			fmt.Fprintln(os.Stderr, "HITSZ Connect: use either -secure-config or -list-secure-configs")
			os.Exit(2)
		}
		// A secure profile supplies its runtime values after this flag phase.
		// Rejecting other flags makes it impossible to accidentally put a secret
		// back into argv while using the encrypted profile workflow.
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "secure-config" && f.Name != "list-secure-configs" {
				fmt.Fprintf(os.Stderr, "HITSZ Connect: -secure-config does not accept -%s; edit the encrypted profile in HITSZ Connect.app\n", f.Name)
				os.Exit(2)
			}
		})
		return
	}

	// A config file supplies defaults; values explicitly supplied on the CLI
	// take precedence. The old behavior silently discarded all CLI values.
	cliValues := map[string]string{}
	flag.Visit(func(f *flag.Flag) { cliValues[f.Name] = f.Value.String() })
	// Make profile-aware utility commands such as -auth-info work when the
	// profile is supplied on the command line. Full config-file merging below
	// applies the same defaults again for normal startup.
	if conf.Profile != "" {
		if err := applyProfile(&conf); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if showVersion {
		fmt.Printf("HITSZ Connect v%s\n", hitszConnectVersion)
		os.Exit(0)
	}

	if atrustAuthInfo {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Auth info is only supported by the atrust protocol")
			os.Exit(1)
		}
		log.SetOutput(io.Discard) // suppress log
		info, err := atrust.GetAuthInfoList(conf.ServerAddress, conf.ServerPort, conf.BindInterface, conf.AutoDetectInterface)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get auth info list error:", err)
			os.Exit(1)
		}
		jsonInfo, err := json.Marshal(info)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error marshaling auth info:", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonInfo))
		os.Exit(0)
	}

	if atrustTrustDevice || atrustUntrustDevice {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device is only supported by the atrust protocol")
			os.Exit(1)
		}
		if conf.ClientDataFile == "" {
			fmt.Fprintln(os.Stderr, "Client data file is required for trust/untrust device")
			os.Exit(1)
		}
		clientData, err := os.ReadFile(conf.ClientDataFile)
		if err != nil {
			log.Printf("Read client data file error: %s", err)
			os.Exit(1)
		}

		err = atrust.SetTrusted(conf.ServerAddress, conf.ServerPort, clientData, atrustTrustDevice, conf.BindInterface, conf.AutoDetectInterface)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device error:", err)
			os.Exit(1)
		}
		if atrustTrustDevice {
			log.Println("Device trusted successfully")
		} else {
			log.Println("Device untrusted successfully")
		}
		os.Exit(0)
	}

	if configFile != "" {
		err := parseTOMLConfig(configFile, &conf)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for name, value := range cliValues {
			if name != "config" {
				_ = flag.Set(name, value)
			}
		}
	} else {
		if tcpPortForwarding != "" {
			forwardingStringList := strings.Split(tcpPortForwarding, ",")
			for _, forwardingString := range forwardingStringList {
				addressStringList := strings.Split(forwardingString, "-")
				if len(addressStringList) != 2 {
					fmt.Fprintln(os.Stderr, "ZJU Connect: wrong tcp port forwarding format")
					os.Exit(1)
				}

				conf.PortForwardingList = append(conf.PortForwardingList, configs.SinglePortForwarding{
					NetworkType:   "tcp",
					BindAddress:   addressStringList[0],
					RemoteAddress: addressStringList[1],
				})
			}
		}

		if udpPortForwarding != "" {
			forwardingStringList := strings.Split(udpPortForwarding, ",")
			for _, forwardingString := range forwardingStringList {
				addressStringList := strings.Split(forwardingString, "-")
				if len(addressStringList) != 2 {
					fmt.Fprintln(os.Stderr, "ZJU Connect: wrong udp port forwarding format")
					os.Exit(1)
				}

				conf.PortForwardingList = append(conf.PortForwardingList, configs.SinglePortForwarding{
					NetworkType:   "udp",
					BindAddress:   addressStringList[0],
					RemoteAddress: addressStringList[1],
				})
			}
		}

		if customDns != "" {
			dnsList := strings.Split(customDns, ",")
			for _, dnsString := range dnsList {
				dnsStringSplit := strings.Split(dnsString, ":")
				if len(dnsStringSplit) != 2 {
					fmt.Fprintln(os.Stderr, "ZJU Connect: wrong custom dns format")
					os.Exit(1)
				}

				conf.CustomDNSList = append(conf.CustomDNSList, configs.SingleCustomDNS{
					HostName: dnsStringSplit[0],
					IP:       dnsStringSplit[1],
				})
			}
		}

		if customProxyDomain != "" {
			domainList := strings.Split(customProxyDomain, ",")
			for _, domain := range domainList {
				var domainRegex = regexp.MustCompile(`^[a-zA-Z\d-]+(\.[a-zA-Z\d-]+)*\.[a-zA-Z]{2,}$`)
				if !domainRegex.MatchString(domain) {
					fmt.Fprintf(os.Stderr, "ZJU Connect: %s is not a valid domain\n", domain)
					os.Exit(1)
				}
				conf.CustomProxyDomain = append(conf.CustomProxyDomain, domain)
			}
		}
	}

	if err := applyProfile(&conf); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	missing := conf.ServerAddress == ""
	if !missing && conf.Protocol == "easyconnect" {
		missing = (conf.Username == "" || conf.Password == "") && conf.TwfID == ""
	}
	if !missing && conf.Protocol == "atrust" {
		switch conf.AuthType {
		case "auth/psw":
			missing = conf.Username == "" || conf.Password == ""
		case "auth/smsCheckCode":
			missing = conf.Phone == ""
		case "auth/hitsz-sso":
			missing = conf.Username == "" || conf.Password == ""
		}
		if missing {
			missing = conf.SID == "" || conf.DeviceID == "" || conf.ResourceFile == ""
		}
	}
	if missing {
		fmt.Println("ZJU Connect: missing required arguments")
		fmt.Println("Please see: https://github.com/mythologyli/zju-connect")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()

		os.Exit(1)
	}

	if conf.Protocol == "atrust" && conf.ServerAddress == "rvpn.zju.edu.cn" {
		fmt.Println("ZJU Connect: set default aTrust server address to vpn.zju.edu.cn")
		conf.ServerAddress = "vpn.zju.edu.cn"
	} else if conf.Protocol == "easyconnect" && conf.ServerAddress == "vpn.zju.edu.cn" {
		fmt.Println("ZJU Connect: set default EasyConnect server address to rvpn.zju.edu.cn")
		conf.ServerAddress = "rvpn.zju.edu.cn"
	}
}
