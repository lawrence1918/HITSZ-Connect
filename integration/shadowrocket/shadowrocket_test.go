package shadowrocket

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestHiddenURLArgumentsDoNotForegroundShadowrocket(t *testing.T) {
	want := []string{"-g", "-j", "shadowrocket://connect"}
	if got := hiddenURLArguments("connect"); !reflect.DeepEqual(got, want) {
		t.Fatalf("hiddenURLArguments() = %v, want %v", got, want)
	}
}

func TestShadowrocketTunnelActiveUsesRunningDescriptor(t *testing.T) {
	active := `utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    agent domain:NetworkExtension type:VPN flags:0x3 desc:"VPN: Shadowrocket"`
	inactive := `utun6: flags=8050<POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    agent domain:NetworkExtension type:VPN flags:0x3 desc:"VPN: Shadowrocket"`
	if !shadowrocketTunnelActive(active) {
		t.Fatal("running Shadowrocket tunnel was not detected")
	}
	if shadowrocketTunnelActive(inactive) {
		t.Fatal("non-UP Shadowrocket tunnel was treated as active")
	}
	if shadowrocketTunnelActive(strings.ReplaceAll(active, "Shadowrocket", "Other VPN")) {
		t.Fatal("unrelated VPN tunnel was treated as Shadowrocket")
	}
}

func TestShadowrocketServiceActiveIncludesConnecting(t *testing.T) {
	for _, state := range []string{"Connected", "Connecting"} {
		line := "* (" + state + ") F8322D9E-E617-4064-8564-0A704D04F3BD VPN (com.liguangming.Shadowrocket)"
		if !shadowrocketServiceActive(line) {
			t.Fatalf("Shadowrocket service state %s was not active", state)
		}
	}
	if shadowrocketServiceActive("* (Disconnected) F832 VPN (com.liguangming.Shadowrocket)") {
		t.Fatal("Disconnected Shadowrocket service was treated as active")
	}
}

func TestDisconnectAndWaitPollsPacketTunnelTruth(t *testing.T) {
	openCalls := 0
	statusCalls := 0
	controller := Controller{
		open: func(_ context.Context, args ...string) error {
			openCalls++
			if !reflect.DeepEqual(args, hiddenURLArguments("disconnect")) {
				t.Fatalf("disconnect open args = %v", args)
			}
			return nil
		},
		tunnelActive: func(context.Context) (bool, error) {
			statusCalls++
			return statusCalls < 2, nil
		},
	}
	if err := controller.DisconnectAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if openCalls != 1 || statusCalls != 2 {
		t.Fatalf("open calls=%d status calls=%d", openCalls, statusCalls)
	}
}

func TestValidateAnyTLSURI(t *testing.T) {
	if err := ValidateAnyTLSURI("anytls://password@example.com:443?security=tls"); err != nil {
		t.Fatalf("valid AnyTLS URI rejected: %v", err)
	}
	for _, raw := range []string{"trojan://x@example.com:443", "anytls://example.com", "anytls://"} {
		if err := ValidateAnyTLSURI(raw); err == nil {
			t.Fatalf("invalid URI accepted: %q", raw)
		}
	}
}

func TestConfigFragment(t *testing.T) {
	fragment := ConfigFragment("127.0.0.1:53535")
	for _, want := range []string{"always-real-ip = *", "hitsz.edu.cn = server:udp://127.0.0.1:53535", "*.hitsz.edu.cn"} {
		if !contains(fragment, want) {
			t.Fatalf("fragment missing %q: %s", want, fragment)
		}
	}
}

func TestHITSZConfigFragmentNormalizesAndSortsRoutes(t *testing.T) {
	fragment := HITSZConfigFragment(
		"localhost:053535",
		":01080",
		[]string{
			"10.250.192.23/32",
			"10.248.98.99/24",
			"10.248.0.0/17",
			"10.248.128.0/17",
			"192.168.1.9/16",
			"172.20.10.1/16",
		},
		[]string{
			"*.NET.HITSZ.EDU.CN.",
			"net.hitsz.edu.cn",
			".ALPHA.HITSZ.EDU.CN.",
			"*.alpha.hitsz.edu.cn",
		},
	)

	for _, want := range []string{
		"[General]\nalways-real-ip = *",
		"[Proxy]\nHITSZ-aTrust = socks5,127.0.0.1,1080",
		"DOMAIN-SUFFIX,alpha.hitsz.edu.cn,HITSZ-aTrust",
		"DOMAIN-SUFFIX,net.hitsz.edu.cn,HITSZ-aTrust",
		"IP-CIDR,10.248.0.0/16,HITSZ-aTrust,no-resolve",
		"IP-CIDR,10.250.192.23/32,HITSZ-aTrust,no-resolve",
		"hitsz.edu.cn = server:udp://127.0.0.1:53535",
		"*.hitsz.edu.cn = server:udp://127.0.0.1:53535",
	} {
		if !strings.Contains(fragment, want) {
			t.Fatalf("fragment missing %q:\n%s", want, fragment)
		}
	}

	ordered := []string{
		"DOMAIN-SUFFIX,alpha.hitsz.edu.cn,HITSZ-aTrust",
		"DOMAIN-SUFFIX,net.hitsz.edu.cn,HITSZ-aTrust",
		"IP-CIDR,10.248.0.0/16,HITSZ-aTrust,no-resolve",
		"IP-CIDR,10.250.192.23/32,HITSZ-aTrust,no-resolve",
	}
	last := -1
	for _, rule := range ordered {
		position := strings.Index(fragment, rule)
		if position <= last {
			t.Fatalf("rules are not sorted:\n%s", fragment)
		}
		last = position
	}
	if strings.Count(fragment, "DOMAIN-SUFFIX,alpha.hitsz.edu.cn,HITSZ-aTrust") != 1 ||
		strings.Count(fragment, "IP-CIDR,10.248.0.0/16,HITSZ-aTrust,no-resolve") != 1 {
		t.Fatalf("duplicate normalized rules were emitted:\n%s", fragment)
	}
}

func TestHITSZConfigFragmentSkipsUnsafeInputs(t *testing.T) {
	fragment := HITSZConfigFragment(
		"remote.example:53535\n[Rule]",
		"127.0.0.1:bad\nDIRECT",
		[]string{
			"10.248.0.0/16",
			"10.251.0.0/16",
			"10.0.0.0/8",
			"10.0.0.0/7",
			"0.0.0.0/0",
			"8.8.8.8/32",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"224.0.0.0/4",
			"::1/128",
			"not-a-cidr",
		},
		[]string{
			"*.Safe.HITSZ.EDU.CN.",
			"safe.hitsz.edu.cn",
			"com",
			"co.uk",
			"bad,rule.example",
			"bad\n[Rule]",
			"*..bad.example",
			"10.1.2.3",
		},
	)

	for _, want := range []string{
		"HITSZ-aTrust = socks5,127.0.0.1,1080",
		"IP-CIDR,10.248.0.0/16,HITSZ-aTrust,no-resolve",
		"DOMAIN-SUFFIX,safe.hitsz.edu.cn,HITSZ-aTrust",
		"hitsz.edu.cn = server:udp://127.0.0.1:53535",
	} {
		if !strings.Contains(fragment, want) {
			t.Fatalf("fragment missing %q:\n%s", want, fragment)
		}
	}
	for _, forbidden := range []string{
		"10.0.0.0/8",
		"10.0.0.0/7",
		"10.251.0.0/16",
		"0.0.0.0/0",
		"8.8.8.8/32",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"::1/128",
		"bad,rule.example",
		"bad\n[Rule]",
		"*..bad.example",
		"10.1.2.3 = server",
		"DOMAIN-SUFFIX,com,HITSZ-aTrust",
		"DOMAIN-SUFFIX,co.uk,HITSZ-aTrust",
	} {
		if strings.Contains(fragment, forbidden) {
			t.Fatalf("unsafe input leaked into fragment as %q:\n%s", forbidden, fragment)
		}
	}
}

func TestHITSZResourceCIDRsLimitsToConfirmedCampusRanges(t *testing.T) {
	got := HITSZResourceCIDRs([]client.IPResource{
		{IPMin: net.ParseIP("10.247.255.255"), IPMax: net.ParseIP("10.251.0.0")},
		{IPMin: net.ParseIP("192.168.43.1"), IPMax: net.ParseIP("192.168.43.1")},
	})
	want := []string{"10.248.0.0/15", "10.250.0.0/16"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("HITSZResourceCIDRs() = %v, want %v", got, want)
	}
}

func contains(s, want string) bool {
	return len(want) == 0 || (len(s) >= len(want) && index(s, want) >= 0)
}
func index(s, want string) int {
	for i := 0; i+len(want) <= len(s); i++ {
		if s[i:i+len(want)] == want {
			return i
		}
	}
	return -1
}
