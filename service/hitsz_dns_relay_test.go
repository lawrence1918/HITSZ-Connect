package service

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testTCPDialer struct{ addr string }

func (d testTCPDialer) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

func TestHITSZDNSRelayOnlyForHITSZDomains(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{Listener: upstreamListener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(10, 1, 2, 3)})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	defer upstream.Shutdown()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bind := probe.Addr().String()
	_ = probe.Close()
	relay, err := StartHITSZDNSRelay(bind, "10.248.98.30", testTCPDialer{addr: upstreamListener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	time.Sleep(10 * time.Millisecond)
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	request := new(dns.Msg)
	request.SetQuestion("portal.hitsz.edu.cn.", dns.TypeA)
	response, _, err := client.Exchange(request, bind)
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("valid HITSZ lookup failed: response=%v err=%v", response, err)
	}
	blocked := new(dns.Msg)
	blocked.SetQuestion("example.com.", dns.TypeA)
	response, _, err = client.Exchange(blocked, bind)
	if err != nil || response.Rcode != dns.RcodeRefused {
		t.Fatalf("non-HITSZ lookup was not refused: response=%v err=%v", response, err)
	}
}
