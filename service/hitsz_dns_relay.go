package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/log"
)

// TCPDNSDialer is intentionally smaller than stack.Stack so the relay is easy
// to test without a live VPN.
type TCPDNSDialer interface {
	DialTCP(context.Context, *net.TCPAddr) (net.Conn, error)
}

// HITSZDNSRelay exposes a loopback DNS endpoint for Shadowrocket. It never
// sends a query through the system resolver: only hitsz.edu.cn is accepted and
// every accepted query is transported over the aTrust TCP stack.
type HITSZDNSRelay struct {
	bindAddr  string
	upstream  *net.TCPAddr
	dialer    TCPDNSDialer
	udp       *dns.Server
	tcp       *dns.Server
	closeOnce sync.Once
}

func StartHITSZDNSRelay(bindAddr, upstream string, dialer TCPDNSDialer) (*HITSZDNSRelay, error) {
	if dialer == nil {
		return nil, fmt.Errorf("HITSZ DNS relay: nil aTrust dialer")
	}
	ip := net.ParseIP(upstream)
	if ip == nil {
		return nil, fmt.Errorf("HITSZ DNS relay: invalid upstream %q", upstream)
	}
	udpConn, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listen HITSZ DNS UDP: %w", err)
	}
	tcpListener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("listen HITSZ DNS TCP: %w", err)
	}
	relay := &HITSZDNSRelay{bindAddr: bindAddr, upstream: &net.TCPAddr{IP: ip, Port: 53}, dialer: dialer}
	handler := dns.HandlerFunc(relay.serveDNS)
	relay.udp = &dns.Server{PacketConn: udpConn, Handler: handler}
	relay.tcp = &dns.Server{Listener: tcpListener, Handler: handler}
	go func() {
		if err := relay.udp.ActivateAndServe(); err != nil {
			log.Printf("HITSZ DNS UDP relay stopped: %v", err)
		}
	}()
	go func() {
		if err := relay.tcp.ActivateAndServe(); err != nil {
			log.Printf("HITSZ DNS TCP relay stopped: %v", err)
		}
	}()
	log.Printf("HITSZ DNS relay listening on %s (TCP upstream %s:53)", bindAddr, upstream)
	return relay, nil
}

func (r *HITSZDNSRelay) serveDNS(w dns.ResponseWriter, request *dns.Msg) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) == 0 || !hitszQuestionsOnly(request.Question) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(response)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := r.dialer.DialTCP(ctx, r.upstream)
	if err != nil {
		r.writeServerFailure(w, request)
		return
	}
	defer conn.Close()
	client := &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
	response, _, err := client.ExchangeWithConn(request, &dns.Conn{Conn: conn})
	if err != nil || response == nil {
		r.writeServerFailure(w, request)
		return
	}
	_ = w.WriteMsg(response)
}

func (r *HITSZDNSRelay) writeServerFailure(w dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = dns.RcodeServerFailure
	_ = w.WriteMsg(response)
}

func hitszQuestionsOnly(questions []dns.Question) bool {
	for _, question := range questions {
		name := strings.TrimSuffix(strings.ToLower(question.Name), ".")
		if name != "hitsz.edu.cn" && !strings.HasSuffix(name, ".hitsz.edu.cn") {
			return false
		}
	}
	return true
}

func (r *HITSZDNSRelay) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		if r.udp != nil {
			closeErr = r.udp.Shutdown()
		}
		if r.tcp != nil {
			if err := r.tcp.Shutdown(); closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}
