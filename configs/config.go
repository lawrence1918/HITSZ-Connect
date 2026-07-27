package configs

type (
	Config struct {
		// Common fields
		Protocol            string // "easyconnect" or "atrust"
		ServerAddress       string
		ServerPort          int
		Username            string
		Password            string
		SocksBind           string
		SocksUser           string
		SocksPasswd         string
		HTTPBind            string
		PortForwardingList  []SinglePortForwarding
		ShadowsocksURL      string
		DialDirectProxy     string
		DisableZJUConfig    bool
		DisableRemoteDNS    bool
		DNSTTL              uint64
		RemoteDNSServer     string
		SecondaryDNSServer  string
		DNSServerBind       string
		CustomDNSList       []SingleCustomDNS
		DisableKeepAlive    bool
		KeepAliveURL        string
		TCPTunnelMode       bool
		TUNMode             bool
		AddRoute            bool
		DNSHijack           bool
		FakeIP              bool
		GraphCodeFile       string
		DebugDump           bool
		BindInterface       string
		AutoDetectInterface bool
		Profile             string
		NoSystemDNSMutation bool

		// HITSZ/aTrust integration fields. These are optional for existing
		// deployments and are enabled by the "hitsz" profile.
		MFAMethod                    string
		MFACode                      string
		MFAOTPSecret                 string
		MFAOTPSecretFile             string
		NonInteractive               bool
		RememberSSO                  bool
		RememberMFA                  bool
		DNSRelayBind                 string
		HITSZDNSServer               string
		Shadowrocket                 string
		ShadowrocketUpdateSubs       bool
		ShadowrocketAddNodeFile      string
		ShadowrocketDisconnectOnExit bool
		ShadowrocketConfigFragment   string

		// EasyConnect fields
		TOTPSecret          string
		CertFile            string
		CertPassword        string
		DisableServerConfig bool
		SkipDomainResource  bool
		DisableMultiLine    bool
		ProxyAll            bool
		CustomProxyDomain   []string
		TwfID               string

		// aTrust fields
		AuthType                string
		Phone                   string
		LoginDomain             string
		ClientDataFile          string
		CasTicket               string
		OAuth2Code              string
		SID                     string
		DeviceID                string
		SignKey                 string
		ResourceFile            string
		UpdateBestNodesInterval int
		SkipTCPTunnelWait       bool
	}

	SinglePortForwarding struct {
		NetworkType   string
		BindAddress   string
		RemoteAddress string
	}

	SingleCustomDNS struct {
		HostName string `toml:"host_name"`
		IP       string `toml:"ip"`
	}
)

type (
	ConfigTOML struct {
		Protocol                     *string                    `toml:"protocol"`
		ServerAddress                *string                    `toml:"server_address"`
		ServerPort                   *int                       `toml:"server_port"`
		Username                     *string                    `toml:"username"`
		Password                     *string                    `toml:"password"`
		TOTPSecret                   *string                    `toml:"totp_secret"`
		CertFile                     *string                    `toml:"cert_file"`
		CertPassword                 *string                    `toml:"cert_password"`
		DisableServerConfig          *bool                      `toml:"disable_server_config"`
		SkipDomainResource           *bool                      `toml:"skip_domain_resource"`
		DisableZJUConfig             *bool                      `toml:"disable_zju_config"`
		DisableRemoteDNS             *bool                      `toml:"disable_zju_dns"` // TODO: rename to disable_remote_dns
		DisableMultiLine             *bool                      `toml:"disable_multi_line"`
		ProxyAll                     *bool                      `toml:"proxy_all"`
		SocksBind                    *string                    `toml:"socks_bind"`
		SocksUser                    *string                    `toml:"socks_user"`
		SocksPasswd                  *string                    `toml:"socks_passwd"`
		HTTPBind                     *string                    `toml:"http_bind"`
		ShadowsocksURL               *string                    `toml:"shadowsocks_url"`
		DialDirectProxy              *string                    `toml:"dial_direct_proxy"`
		TCPTunnelMode                *bool                      `toml:"tcp_tunnel_mode"`
		TUNMode                      *bool                      `toml:"tun_mode"`
		AddRoute                     *bool                      `toml:"add_route"`
		DNSTTL                       *uint64                    `toml:"dns_ttl"`
		DisableKeepAlive             *bool                      `toml:"disable_keep_alive"`
		KeepAliveURL                 *string                    `toml:"keep_alive_url"`
		RemoteDNSServer              *string                    `toml:"zju_dns_server"` // TODO: rename to remote_dns_server
		SecondaryDNSServer           *string                    `toml:"secondary_dns_server"`
		DNSServerBind                *string                    `toml:"dns_server_bind"`
		DNSHijack                    *bool                      `toml:"dns_hijack"`
		FakeIP                       *bool                      `toml:"fake_ip"`
		GraphCodeFile                *string                    `toml:"graph_code_file"`
		DebugDump                    *bool                      `toml:"debug_dump"`
		PortForwarding               []SinglePortForwardingTOML `toml:"port_forwarding"`
		CustomDNS                    []SingleCustomDNSTOML      `toml:"custom_dns"`
		CustomProxyDomain            []string                   `toml:"custom_proxy_domain"`
		AuthType                     *string                    `toml:"auth_type"`
		Phone                        *string                    `toml:"phone"`
		LoginDomain                  *string                    `toml:"login_domain"`
		ClientDataFile               *string                    `toml:"client_data_file"`
		CasTicket                    *string                    `toml:"cas_ticket"`
		OAuth2Code                   *string                    `toml:"oauth2_code"`
		SID                          *string                    `toml:"sid"`
		DeviceID                     *string                    `toml:"device_id"`
		SignKey                      *string                    `toml:"sign_key"`
		ResourceFile                 *string                    `toml:"resource_file"`
		UpdateBestNodesInterval      *int                       `toml:"update_best_nodes_interval"`
		SkipTCPTunnelWait            *bool                      `toml:"skip_tcp_tunnel_wait"`
		BindInterface                *string                    `toml:"bind_interface"`
		AutoDetectInterface          *bool                      `toml:"auto_detect_interface"`
		Profile                      *string                    `toml:"profile"`
		NoSystemDNSMutation          *bool                      `toml:"no_system_dns_mutation"`
		MFAMethod                    *string                    `toml:"mfa_method"`
		MFACode                      *string                    `toml:"mfa_code"`
		MFAOTPSecret                 *string                    `toml:"mfa_otp_secret"`
		MFAOTPSecretFile             *string                    `toml:"mfa_otp_secret_file"`
		NonInteractive               *bool                      `toml:"non_interactive"`
		RememberSSO                  *bool                      `toml:"remember_sso"`
		RememberMFA                  *bool                      `toml:"remember_mfa"`
		DNSRelayBind                 *string                    `toml:"dns_relay_bind"`
		HITSZDNSServer               *string                    `toml:"hitsz_dns_server"`
		Shadowrocket                 *string                    `toml:"shadowrocket"`
		ShadowrocketUpdateSubs       *bool                      `toml:"shadowrocket_update_subs"`
		ShadowrocketAddNodeFile      *string                    `toml:"shadowrocket_add_node_file"`
		ShadowrocketDisconnectOnExit *bool                      `toml:"shadowrocket_disconnect_on_exit"`
		ShadowrocketConfigFragment   *string                    `toml:"shadowrocket_config_fragment"`
	}

	SinglePortForwardingTOML struct {
		NetworkType   *string `toml:"network_type"`
		BindAddress   *string `toml:"bind_address"`
		RemoteAddress *string `toml:"remote_address"`
	}

	SingleCustomDNSTOML struct {
		HostName *string `toml:"host_name"`
		IP       *string `toml:"ip"`
	}
)
