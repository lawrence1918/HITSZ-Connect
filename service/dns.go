package service

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

type DNSServer struct {
	resolver *resolve.Resolver
	localDNS []net.IP
}

func (d DNSServer) serveDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	_ = d.handleSingleDNSResolve(context.Background(), r, m)

	_ = w.WriteMsg(m)
}

func (d DNSServer) HandleDnsMsg(ctx context.Context, requestMsg *dns.Msg) (*dns.Msg, error) {
	resMsg := new(dns.Msg)
	resMsg.SetReply(requestMsg)
	resMsg.Compress = false

	err := d.handleSingleDNSResolve(ctx, requestMsg, resMsg)
	return resMsg, err
}

func (d DNSServer) CheckDnsHijack(dstIP net.IP) bool {
	for _, ip := range d.localDNS {
		if ip.Equal(dstIP) {
			return false
		}
	}
	return true
}

func (d DNSServer) handleSingleDNSResolve(ctx context.Context, requestMsg *dns.Msg, resMsg *dns.Msg) error {
	switch requestMsg.Opcode {
	case dns.OpcodeQuery:
		for _, q := range requestMsg.Question {
			name := q.Name
			if len(name) > 1 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}

			switch q.Qtype {
			case dns.TypeA:
				if _, ip, err := d.resolver.Resolve(ctx, name); err == nil {
					if ip.To4() != nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
						if err == nil {
							resMsg.Answer = append(resMsg.Answer, rr)
						}
					} else {
						resMsg.Rcode = dns.RcodeServerFailure
					}
				}
			case dns.TypeAAAA:
				if _, ip, err := d.resolver.Resolve(ctx, name); err == nil {
					if ip.To4() == nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
						if err == nil {
							resMsg.Answer = append(resMsg.Answer, rr)
						}
					} else {
						resMsg.Rcode = dns.RcodeServerFailure
					}
				}
			}
		}
	}
	return nil
}

func NewDnsServer(resolver *resolve.Resolver, dnsServers []string) DNSServer {
	netIPs := make([]net.IP, 0, len(dnsServers))
	for _, dnsServer := range dnsServers {
		if net.ParseIP(dnsServer) != nil {
			netIPs = append(netIPs, net.ParseIP(dnsServer))
		}
	}
	return DNSServer{resolver: resolver, localDNS: netIPs}
}

type DNSHandle struct {
	udp  *dns.Server
	tcp  *dns.Server
	once sync.Once
}

func StartDNS(bindAddr string, dnsServer DNSServer) (*DNSHandle, error) {
	udpConn, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		return nil, err
	}
	tcpListener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	handler := dns.HandlerFunc(dnsServer.serveDNSRequest)
	handle := &DNSHandle{
		udp: &dns.Server{PacketConn: udpConn, Handler: handler},
		tcp: &dns.Server{Listener: tcpListener, Handler: handler},
	}
	go func() {
		if err := handle.udp.ActivateAndServe(); err != nil {
			log.Printf("DNS UDP server stopped: %v", err)
		}
	}()
	go func() {
		if err := handle.tcp.ActivateAndServe(); err != nil {
			log.Printf("DNS TCP server stopped: %v", err)
		}
	}()
	log.Printf("Starting DNS server at %s (UDP/TCP)", bindAddr)
	return handle, nil
}

func (h *DNSHandle) Close() error {
	var closeErr error
	h.once.Do(func() {
		if h.udp != nil {
			closeErr = h.udp.Shutdown()
		}
		if h.tcp != nil {
			if err := h.tcp.Shutdown(); closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

func ServeDNS(bindAddr string, dnsServer DNSServer) {
	handle, err := StartDNS(bindAddr, dnsServer)
	if err != nil {
		log.Println("DNS server listen failed: " + err.Error())
		return
	}

	hook_func.RegisterTerminalFunc("CloseDNSListener", func(ctx context.Context) error {
		log.Println("Closing DNS listener...")
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close DNS listener failed: %w", err)
		}
		return nil
	})
}
