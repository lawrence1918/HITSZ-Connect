package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/containers/winquit/pkg/winquit"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	atrustauth "github.com/mythologyli/zju-connect/client/atrust/auth"
	easyconnectclient "github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/integration/shadowrocket"
	"github.com/mythologyli/zju-connect/internal/appbridge"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/internal/metrics"
	"github.com/mythologyli/zju-connect/internal/secureconfig"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tcptunnel"
	"github.com/mythologyli/zju-connect/stack/tun"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
)

var conf configs.Config

type bridgeRuntime struct {
	session      *appbridge.Session
	start        appbridge.StartRequest
	listeners    appbridge.ListenerStatus
	statusCancel context.CancelFunc
}

// secureConfigRuntime keeps the authenticated aTrust session state in the
// same encrypted profile that supplied this invocation. It is intentionally
// separate from the App bridge: the bridge owns its state in the GUI process,
// while this path lets users safely reconnect from the formal CLI without
// passing credentials on the command line.
type secureConfigRuntime struct {
	store      *secureconfig.Store
	connection secureconfig.StoredConnection
}

var activeBridge *bridgeRuntime
var activeSecureConfig *secureConfigRuntime

func main() {
	log.Init()
	if listSecureConfigs {
		if err := printSecureConfigs(); err != nil {
			log.Fatalf("List encrypted connections: %s", err)
		}
		return
	}
	if secureConfigID != "" {
		if err := loadSecureConfig(secureConfigID); err != nil {
			log.Fatalf("Load encrypted connection: %s", err)
		}
	}
	if appBridge {
		// The standard logger and package-specific loggers must never share the
		// bridge's stdout NDJSON stream.
		stdlog.SetOutput(os.Stderr)
		session := appbridge.New(os.Stdin, os.Stdout)
		start, err := session.ReadStart(conf)
		if err != nil {
			_ = session.EmitError(err)
			_ = session.EmitStopped("bridge start rejected")
			return
		}
		conf = start.Config
		if conf.Profile == "" {
			conf.Profile = "hitsz"
		}
		appbridge.PrepareRuntimeConfig(&conf)
		if err := applyProfile(&conf); err != nil {
			_ = session.EmitError(err)
			_ = session.EmitStopped("invalid bridge configuration")
			return
		}
		if err := validateBridgeConfig(conf); err != nil {
			_ = session.EmitError(err)
			_ = session.EmitStopped("invalid bridge configuration")
			return
		}
		activeBridge = &bridgeRuntime{session: session, start: start}
		metrics.ResetATrust()
		session.StartCommandLoop()
		restoreMFAProvider := atrustauth.SetHITSZMFACodeProvider(session.RequestMFACode)
		defer restoreMFAProvider()
		_ = session.EmitPhase("starting", "Starting HITSZ Connect")
	}

	if CommitID != "" {
		log.Println("Start HITSZ Connect v" + hitszConnectVersion + "-" + CommitID)
	} else {
		log.Println("Start HITSZ Connect v" + hitszConnectVersion)
	}
	if conf.DebugDump {
		log.EnableDebug()
	}

	if errs := hook_func.ExecInitialFunc(context.Background(), conf); errs != nil {
		fatalf("initial HITSZ Connect setup failed: %v", errors.Join(errs...))
	}
	emitBridgePhase("authenticating", "Authenticating with aTrust")

	var vpnClient client.Client
	switch conf.Protocol {
	case "easyconnect":
		tlsCert := tls.Certificate{}
		if conf.CertFile != "" {
			p12Data, err := os.ReadFile(conf.CertFile)
			if err != nil {
				fatalf("Read certificate file error: %s", err)
			}

			key, cert, err := pkcs12.Decode(p12Data, conf.CertPassword)
			if err != nil {
				fatalf("Decode certificate file error: %s", err)
			}

			tlsCert = tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key.(crypto.PrivateKey),
				Leaf:        cert,
			}
		}

		vpnClient = easyconnectclient.NewClient(
			conf.ServerAddress+":"+fmt.Sprintf("%d", conf.ServerPort),
			conf.Username,
			conf.Password,
			conf.TOTPSecret,
			tlsCert,
			conf.TwfID,
			!conf.DisableMultiLine,
			!conf.DisableServerConfig,
			!conf.SkipDomainResource,
		)

		log.Printf("VPN protocol: %s", conf.Protocol)
		err := vpnClient.(*easyconnectclient.Client).Setup(conf.GraphCodeFile, conf.BindInterface, conf.AutoDetectInterface)
		if err != nil {
			fatalf("VPN client setup error: %s", err)
		}
	case "atrust":
		var err error
		var resourceData []byte

		if conf.ResourceFile != "" {
			resourceData, err = os.ReadFile(conf.ResourceFile)
			if err != nil {
				fatalf("Read resource file error: %s", err)
			}
		}

		var clientData []byte
		if activeBridge != nil && activeBridge.start.ClientDataProvided {
			clientData = append([]byte(nil), activeBridge.start.ClientData...)
		} else if activeSecureConfig != nil {
			clientData = activeSecureConfig.connection.ClientDataCopy()
		} else if conf.ClientDataFile != "" {
			clientData, err = os.ReadFile(conf.ClientDataFile)
			if err != nil {
				log.Printf("Read client data file error: %s", err)
				log.Println("Will create a new client data file if log in successfully")
			}
		}

		vpnClient = atrustclient.NewClient(conf.Username, conf.SID, conf.DeviceID, conf.SignKey)
		vpnClient.(*atrustclient.Client).SetSkipTCPTunnelWait(conf.SkipTCPTunnelWait)

		log.Printf("VPN protocol: %s", conf.Protocol)
		clientData, err = vpnClient.(*atrustclient.Client).Setup(
			conf.ServerAddress,
			conf.ServerPort,
			conf.Username,
			conf.Password,
			conf.Phone,
			conf.LoginDomain,
			conf.AuthType,
			conf.GraphCodeFile,
			conf.CasTicket,
			conf.OAuth2Code,
			conf.MFAMethod,
			conf.MFACode,
			conf.MFAOTPSecret,
			conf.MFAOTPSecretFile,
			conf.NonInteractive,
			conf.RememberSSO,
			conf.RememberMFA,
			clientData,
			resourceData,
			conf.UpdateBestNodesInterval,
			conf.BindInterface,
			conf.AutoDetectInterface,
		)
		if err != nil {
			fatalf("VPN client setup error: %s", err)
		}
		if activeBridge != nil {
			if err := activeBridge.session.EmitClientData(clientData); err != nil {
				fatalf("emit client data: %s", err)
			}
		}
		if activeSecureConfig != nil {
			activeSecureConfig.connection.ClientData = append([]byte(nil), clientData...)
			updated, saveErr := activeSecureConfig.store.Save(activeSecureConfig.connection)
			if saveErr != nil {
				fatalf("Update encrypted aTrust session: %s", saveErr)
			}
			activeSecureConfig.connection = updated
			log.Println("aTrust session data updated in encrypted connection profile")
		}

		if conf.ClientDataFile != "" {
			err = os.WriteFile(conf.ClientDataFile, clientData, 0600)
			if err != nil {
				fatalf("Write client data file error: %s", err)
			}
			log.Printf("Client data saved to %s", conf.ClientDataFile)
		}
	default:
		fatalf("Unsupported VPN protocol: %s", conf.Protocol)
	}

	log.Printf("VPN client started")
	emitBridgePhase("startingServices", "Starting local listeners")
	if closer, ok := vpnClient.(interface{ Close() }); ok {
		hook_func.RegisterTerminalFunc("CloseVPNClient", func(ctx context.Context) error {
			closer.Close()
			return nil
		})
	}

	ipResources, err := vpnClient.IPResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP resources")
	}

	ipSet, err := vpnClient.IPSet()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP set")
	}

	domainResources, err := vpnClient.DomainResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No domain resources")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No DNS resource")
	}

	if conf.Protocol == "easyconnect" {
		if !conf.DisableZJUConfig {
			if domainResources == nil {
				domainResources = make(map[string]client.DomainResource)
			}

			domainResources["zju.edu.cn"] = client.DomainResource{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}

			if ipResources == nil {
				ipResources = []client.IPResource{}
			}

			ipResources = append([]client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}, ipResources...)

			ipSetBuilder := netaddr.IPSetBuilder{}
			if ipSet != nil {
				ipSetBuilder.AddSet(ipSet)
			}
			ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
			ipSet, _ = ipSetBuilder.IPSet()
		}

		for _, customProxyDomain := range conf.CustomProxyDomain {
			if domainResources != nil {
				domainResources[customProxyDomain] = client.DomainResource{
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				}
			} else {
				domainResources = map[string]client.DomainResource{
					customProxyDomain: {
						PortMin:  1,
						PortMax:  65535,
						Protocol: "all",
					},
				}
			}
		}
	}

	var vpnStack stack.Stack
	if conf.TCPTunnelMode {
		vpnStack, err = tcptunnel.NewStack(vpnClient)
		if err != nil {
			fatalf("TCP Tunnel stack setup error: %s", err)
		}
	} else if conf.TUNMode {
		vpnTUNStack, err := tun.NewStack(vpnClient, conf.DNSHijack, conf.FakeIP, ipResources)
		if err != nil {
			fatalf("Tun stack setup error, make sure you are root user : %s", err)
		}

		if conf.AddRoute && ipSet != nil {
			for _, prefix := range ipSet.Prefixes() {
				log.Printf("Add route to %s", prefix.String())
				_ = vpnTUNStack.AddRoute(prefix.String())
			}
		} else if !conf.AddRoute && !conf.DisableZJUConfig && conf.Protocol == "easyconnect" {
			log.Println("Add route to 10.0.0.0/8")
			_ = vpnTUNStack.AddRoute("10.0.0.0/8")
		}

		if conf.FakeIP {
			_ = vpnTUNStack.AddRoute("198.18.0.0/16")
		}

		vpnStack = vpnTUNStack
	} else {
		vpnStack, err = gvisor.NewStack(vpnClient)
		if err != nil {
			fatalf("gVisor stack setup error: %s", err)
		}
	}

	useRemoteDNS := !conf.DisableRemoteDNS
	remoteDNSServer := conf.RemoteDNSServer
	if useRemoteDNS && remoteDNSServer == "auto" {
		remoteDNSServer, err = vpnClient.DNSServer()
		if err != nil {
			useRemoteDNS = false
			remoteDNSServer = "10.10.0.21"
			log.Println("No DNS server provided by server. Disable remote DNS")
		} else {
			log.Printf("Use DNS server %s provided by server", remoteDNSServer)
		}
	}

	vpnResolver := resolve.NewResolver(
		vpnStack,
		remoteDNSServer,
		conf.SecondaryDNSServer,
		conf.DNSTTL,
		domainResources,
		dnsResource,
		useRemoteDNS,
	)
	hook_func.RegisterTerminalFunc("CloseResolver", func(ctx context.Context) error {
		vpnResolver.Close()
		return nil
	})

	for _, customDns := range conf.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{remoteDNSServer, conf.SecondaryDNSServer})
	vpnStack.SetupResolve(localResolver)
	vpnStack.SetupIPPool(vpnResolver.IPPool)

	go vpnStack.Run()

	// In the HITSZ profile the SOCKS endpoint is the data-plane bridge for
	// Shadowrocket. Bind it before invoking Shadowrocket's connect URL so the
	// packet tunnel can never race a not-yet-listening local proxy.
	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResources, conf.ProxyAll, conf.DialDirectProxy)
	if conf.SocksBind != "" {
		if err := service.ServeSocks5(conf.SocksBind, vpnDialer, vpnResolver, conf.SocksUser, conf.SocksPasswd); err != nil {
			fatalf("SOCKS5 server setup error: %s", err)
		}
		if activeBridge != nil {
			activeBridge.listeners.Socks = true
		}
	}

	// The HITSZ relay is intentionally independent of the legacy resolver:
	// Shadowrocket sends only *.hitsz.edu.cn here, and every accepted request
	// is forwarded through aTrust rather than the macOS resolver.
	if conf.Profile == "hitsz" && conf.DNSRelayBind != "" {
		relay, relayErr := service.StartHITSZDNSRelay(conf.DNSRelayBind, conf.HITSZDNSServer, vpnStack)
		if relayErr != nil {
			fatalf("HITSZ DNS relay setup error: %s", relayErr)
		}
		if activeBridge != nil {
			activeBridge.listeners.DNSRelay = true
		}
		hook_func.RegisterTerminalFunc("CloseHITSZDNSRelay", func(ctx context.Context) error {
			return relay.Close()
		})
	}

	if conf.ShadowrocketConfigFragment != "" {
		fragment := shadowrocket.ConfigFragment(conf.DNSRelayBind)
		if conf.Profile == "hitsz" {
			prefixes := shadowrocket.HITSZResourceCIDRs(ipResources)
			domains := make([]string, 0, len(domainResources)+1)
			domains = append(domains, "hitsz.edu.cn")
			for domain := range domainResources {
				domains = append(domains, domain)
			}
			fragment = shadowrocket.HITSZConfigFragment(conf.DNSRelayBind, conf.SocksBind, prefixes, domains)
		}
		if err := os.WriteFile(conf.ShadowrocketConfigFragment, []byte(fragment), 0600); err != nil {
			fatalf("Write Shadowrocket config fragment error: %s", err)
		}
		log.Printf("Shadowrocket config fragment saved to %s", conf.ShadowrocketConfigFragment)
	}
	if conf.Shadowrocket != "off" || conf.ShadowrocketAddNodeFile != "" || conf.ShadowrocketUpdateSubs {
		controller := shadowrocket.New()
		if err := controller.Apply(context.Background(), conf.Shadowrocket, conf.ShadowrocketAddNodeFile, conf.ShadowrocketUpdateSubs); err != nil {
			fatalf("Shadowrocket integration error: %s", err)
		}
		if conf.ShadowrocketDisconnectOnExit && conf.Shadowrocket == "connect" {
			hook_func.RegisterTerminalFunc("DisconnectShadowrocket", func(ctx context.Context) error {
				return controller.Disconnect(ctx)
			})
		}
	}

	if conf.DNSServerBind != "" {
		go service.ServeDNS(conf.DNSServerBind, localResolver)
	}
	if conf.TUNMode {
		clientIP, _ := vpnClient.IP()
		go service.ServeDNS(clientIP.String()+":53", localResolver)
	}

	if conf.HTTPBind != "" {
		go service.ServeHTTP(conf.HTTPBind, vpnDialer)
		if activeBridge != nil {
			readyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := appbridge.WaitForTCPReady(readyCtx, conf.HTTPBind)
			cancel()
			if err != nil {
				fatalf("HTTP listener setup error: %s", err)
			}
			activeBridge.listeners.HTTP = true
		}
	}

	if conf.ShadowsocksURL != "" {
		go service.ServeShadowsocks(vpnDialer, conf.ShadowsocksURL)
	}

	for _, portForwarding := range conf.PortForwardingList {
		switch portForwarding.NetworkType {
		case "tcp":
			go service.ServeTCPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		case "udp":
			go service.ServeUDPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		default:
			log.Printf("Port forwarding: unknown network type %s. Aborting", portForwarding.NetworkType)
		}
	}

	if !conf.DisableKeepAlive {
		if conf.KeepAliveURL == "" && !useRemoteDNS {
			log.Println("Keep alive is disabled because remote DNS is disabled, and no KeepAliveURL is provided")
		} else {
			keepAliveCtx, keepAliveCancel := context.WithCancel(context.Background())
			hook_func.RegisterTerminalFunc("CloseKeepAlive", func(ctx context.Context) error {
				keepAliveCancel()
				return nil
			})
			go service.KeepAlive(keepAliveCtx, vpnResolver, vpnDialer, conf.KeepAliveURL)
		}
	}

	if activeBridge != nil {
		activeBridge.listeners.Ready =
			(conf.SocksBind == "" || activeBridge.listeners.Socks) &&
				(conf.HTTPBind == "" || activeBridge.listeners.HTTP) &&
				(conf.Profile != "hitsz" || conf.DNSRelayBind == "" || activeBridge.listeners.DNSRelay)
		traffic := metrics.ATrustSnapshot()
		_ = activeBridge.session.Emit(appbridge.Event{
			Type:      "ready",
			State:     "connected",
			Message:   "HITSZ Connect is ready",
			ATrust:    &appbridge.ATrustStatus{Connected: true, RXBytes: traffic.RXBytes, TXBytes: traffic.TXBytes},
			Listeners: &activeBridge.listeners,
		})
		statusCtx, statusCancel := context.WithCancel(context.Background())
		activeBridge.statusCancel = statusCancel
		go emitBridgeStatus(statusCtx, activeBridge)
	}

	waitForShutdown()
	if activeBridge != nil {
		if activeBridge.statusCancel != nil {
			activeBridge.statusCancel()
		}
		_ = activeBridge.session.EmitPhase("stopping", "Stopping HITSZ Connect")
	}
	log.Println("Shutdown HITSZ Connect ......")
	shutdownErrs := hook_func.ExecTerminalFunc(context.Background())
	if shutdownErrs != nil {
		for _, err := range shutdownErrs {
			log.Printf("Shutdown HITSZ Connect failed: %s", err)
		}
		if activeBridge != nil {
			_ = activeBridge.session.EmitError(errors.Join(shutdownErrs...))
		}
	} else {
		log.Println("Shutdown HITSZ Connect success, Bye~")
	}
	if activeBridge != nil {
		_ = activeBridge.session.EmitStopped("HITSZ Connect stopped")
	}
}

func validateBridgeConfig(config configs.Config) error {
	if config.Protocol != "atrust" {
		return errors.New("app bridge currently supports only the atrust protocol")
	}
	if strings.TrimSpace(config.ServerAddress) == "" || config.ServerPort <= 0 {
		return errors.New("aTrust server address and port are required")
	}
	if config.AuthType == "auth/hitsz-sso" && (strings.TrimSpace(config.Username) == "" || config.Password == "") {
		return errors.New("HITSZ username and password are required")
	}
	return nil
}

func printSecureConfigs() error {
	store, err := secureconfig.NewDefaultStore()
	if err != nil {
		return err
	}
	connections, err := store.List()
	if err != nil {
		return err
	}
	if len(connections) == 0 {
		fmt.Println("No encrypted connections in", store.Dir())
		return nil
	}
	for _, connection := range connections {
		fmt.Printf("%s\t%s\t%s\n", connection.ID, connection.Name, connection.UpdatedAt.Format(time.RFC3339))
	}
	return nil
}

func loadSecureConfig(id string) error {
	store, err := secureconfig.NewDefaultStore()
	if err != nil {
		return err
	}
	connection, err := store.Load(id)
	if err != nil {
		return err
	}
	loaded := connection.ToConfig()
	if err := applyProfile(&loaded); err != nil {
		return err
	}
	if loaded.Protocol == "atrust" && loaded.ServerAddress == "rvpn.zju.edu.cn" {
		loaded.ServerAddress = "vpn.zju.edu.cn"
	} else if loaded.Protocol == "easyconnect" && loaded.ServerAddress == "vpn.zju.edu.cn" {
		loaded.ServerAddress = "rvpn.zju.edu.cn"
	}
	if err := validateSecureConfigRuntime(loaded); err != nil {
		return err
	}
	conf = loaded
	activeSecureConfig = &secureConfigRuntime{store: store, connection: connection}
	return nil
}

func validateSecureConfigRuntime(config configs.Config) error {
	if strings.TrimSpace(config.ServerAddress) == "" || config.ServerPort <= 0 {
		return errors.New("encrypted connection is missing a server address or port")
	}
	if config.Profile == "hitsz" || config.AuthType == "auth/hitsz-sso" {
		if strings.TrimSpace(config.Username) == "" || config.Password == "" {
			return errors.New("encrypted HITSZ connection is missing a username or password")
		}
		if strings.EqualFold(config.MFAMethod, "otp") && strings.TrimSpace(config.MFAOTPSecret) == "" {
			return errors.New("encrypted HITSZ OTP connection is missing its OTP seed")
		}
	}
	return nil
}

func emitBridgePhase(phase, message string) {
	if activeBridge == nil {
		return
	}
	if err := activeBridge.session.EmitPhase(phase, message); err != nil {
		activeBridge.session.RequestStop()
	}
}

func emitBridgeStatus(ctx context.Context, bridge *bridgeRuntime) {
	previous := metrics.ATrustSnapshot()
	previousAt := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			current := metrics.ATrustSnapshot()
			seconds := now.Sub(previousAt).Seconds()
			if seconds <= 0 {
				seconds = 1
			}
			rxDelta, txDelta := uint64(0), uint64(0)
			if current.RXBytes >= previous.RXBytes {
				rxDelta = current.RXBytes - previous.RXBytes
			}
			if current.TXBytes >= previous.TXBytes {
				txDelta = current.TXBytes - previous.TXBytes
			}
			event := appbridge.Event{
				Type:      "status",
				State:     "connected",
				Message:   "aTrust connected",
				Listeners: &bridge.listeners,
				ATrust: &appbridge.ATrustStatus{
					Connected:        true,
					RXBytes:          current.RXBytes,
					TXBytes:          current.TXBytes,
					RXBytesPerSecond: float64(rxDelta) / seconds,
					TXBytesPerSecond: float64(txDelta) / seconds,
				},
			}
			if err := bridge.session.Emit(event); err != nil {
				bridge.session.RequestStop()
				return
			}
			previous, previousAt = current, now
		}
	}
}

func waitForShutdown() {
	quit := make(chan os.Signal, 1)
	if runtime.GOOS == "windows" {
		signal.Notify(quit, syscall.SIGINT)
		winquit.SimulateSigTermOnQuit(quit)
	} else {
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	}
	defer signal.Stop(quit)

	if activeBridge == nil {
		<-quit
		return
	}
	select {
	case <-activeBridge.session.StopChan():
	case <-quit:
		activeBridge.session.RequestStop()
	}
}

func fatalf(format string, values ...any) {
	err := fmt.Errorf(format, values...)
	if activeBridge != nil {
		if activeBridge.statusCancel != nil {
			activeBridge.statusCancel()
		}
		_ = activeBridge.session.EmitError(err)
		cleanupErrs := hook_func.ExecTerminalFunc(context.Background())
		if cleanupErrs != nil {
			_ = activeBridge.session.EmitError(errors.Join(cleanupErrs...))
		}
		_ = activeBridge.session.EmitStopped("HITSZ Connect stopped after an error")
	}
	log.Fatalf("%s", err)
}
