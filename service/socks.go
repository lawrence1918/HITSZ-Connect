package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// ServeSocks5 binds synchronously and then serves in the background. This
// lets callers safely hand the loopback proxy address to another application
// (notably Shadowrocket) only after it is ready to accept connections.
func ServeSocks5(bindAddr string, dialer *dial.Dialer, resolver *resolve.Resolver, user string, password string) error {
	var authMethods []socks5.Authenticator
	if user != "" && password != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{user: password},
		})

		log.Println("Neither traffic nor credentials are encrypted in the SOCKS5 protocol!")
		log.Println("DO NOT deploy it to the public network. All consequences and responsibilities have nothing to do with the developer")
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	server := socks5.NewServer(
		socks5.WithAuthMethods(authMethods),
		socks5.WithResolver(resolver),
		socks5.WithDial(dialer.DialIPPort),
		socks5.WithAssociateHandle(loopbackUDPAssociateHandler(dialer)),
		socks5.WithLogger(socks5.NewLogger(log.NewLogger("[SOCKS5] "))),
	)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen failed: %w", err)
	}
	log.Printf("SOCKS5 server listening on %s", bindAddr)

	hook_func.RegisterTerminalFunc("CloseSocks5Listener", func(ctx context.Context) error {
		log.Println("Closing SOCKS5 listener...")
		if err := listener.Close(); err != nil {
			return fmt.Errorf("close SOCKS5 listener failed: %w", err)
		}
		return nil
	})

	go func() {
		if err = server.Serve(listener); err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("SOCKS5 server closed")
			} else {
				log.Println("SOCKS5 listen failed: " + err.Error())
			}
		}
	}()
	return nil
}

// loopbackUDPAssociateHandler implements SOCKS5 UDP ASSOCIATE for local
// clients such as Shadowrocket. Some clients put their intended destination
// port in the TCP request, then use a different ephemeral port for their UDP
// packets. The upstream go-socks5 handler rejects those packets, which makes
// UDP-only applications (for example Moonlight) fail silently. We accept port
// changes only for the loopback peer that owns the TCP control connection.
func loopbackUDPAssociateHandler(dialer *dial.Dialer) func(context.Context, io.Writer, *socks5.Request) error {
	return func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		controlAddr, ok := request.RemoteAddr.(*net.TCPAddr)
		if !ok || controlAddr.IP == nil || !controlAddr.IP.IsLoopback() {
			if err := socks5.SendReply(writer, statute.RepRuleFailure, nil); err != nil {
				return fmt.Errorf("reply to non-loopback UDP associate: %w", err)
			}
			return errors.New("UDP associate is limited to loopback clients")
		}

		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			if replyErr := socks5.SendReply(writer, statute.RepServerFailure, nil); replyErr != nil {
				return fmt.Errorf("listen UDP: %w; reply: %v", err, replyErr)
			}
			return fmt.Errorf("listen UDP: %w", err)
		}
		if err := socks5.SendReply(writer, statute.RepSuccess, listener.LocalAddr()); err != nil {
			listener.Close()
			return fmt.Errorf("reply to UDP associate: %w", err)
		}

		association := &loopbackUDPAssociation{
			listener:  listener,
			dialer:    dialer,
			controlIP: controlAddr.IP,
			conns:     make(map[string]*loopbackUDPConnection),
		}
		done := make(chan struct{})
		go func() {
			association.serve(ctx)
			close(done)
		}()

		// SOCKS5 specifies that the association remains valid only while the TCP
		// control connection is open. The buffered request reader blocks here
		// until Shadowrocket closes that connection.
		buf := make([]byte, 1)
		_, readErr := request.Reader.Read(buf)
		association.close()
		<-done
		if readErr == nil || errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
			return nil
		}
		return readErr
	}
}

type loopbackUDPAssociation struct {
	listener  *net.UDPConn
	dialer    *dial.Dialer
	controlIP net.IP

	mu         sync.RWMutex
	clientAddr *net.UDPAddr
	conns      map[string]*loopbackUDPConnection
	closeOnce  sync.Once
}

type loopbackUDPConnection struct {
	conn   net.Conn
	header []byte
}

func (a *loopbackUDPAssociation) serve(ctx context.Context) {
	buf := make([]byte, BufferSize)
	for {
		n, source, err := a.listener.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !source.IP.IsLoopback() || !source.IP.Equal(a.controlIP) {
			continue
		}
		packet, err := statute.ParseDatagram(buf[:n])
		if err != nil || packet.Frag != 0 {
			continue
		}

		// Shadowrocket may legitimately select a new local UDP source port after
		// its TCP ASSOCIATE request. Keep the latest loopback endpoint for replies.
		a.mu.Lock()
		a.clientAddr = source
		key := packet.DstAddr.String()
		entry := a.conns[key]
		if entry == nil {
			conn, dialErr := a.dialer.DialIPPort(ctx, "udp", key)
			if dialErr == nil {
				entry = &loopbackUDPConnection{conn: conn, header: append([]byte(nil), packet.Header()...)}
				a.conns[key] = entry
				go a.copyReply(key, entry)
			} else {
				log.Printf("SOCKS5 UDP dial %s failed: %v", key, dialErr)
			}
		}
		a.mu.Unlock()
		if entry == nil {
			continue
		}
		if _, err := entry.conn.Write(packet.Data); err != nil {
			log.Printf("SOCKS5 UDP write %s failed: %v", key, err)
		}
	}
}

func (a *loopbackUDPAssociation) copyReply(key string, entry *loopbackUDPConnection) {
	buf := make([]byte, BufferSize)
	for {
		n, err := entry.conn.Read(buf)
		if err != nil {
			a.mu.Lock()
			if a.conns[key] == entry {
				delete(a.conns, key)
			}
			a.mu.Unlock()
			return
		}
		a.mu.RLock()
		client := a.clientAddr
		a.mu.RUnlock()
		if client == nil {
			continue
		}
		reply := make([]byte, len(entry.header)+n)
		copy(reply, entry.header)
		copy(reply[len(entry.header):], buf[:n])
		if _, err := a.listener.WriteToUDP(reply, client); err != nil {
			return
		}
	}
}

func (a *loopbackUDPAssociation) close() {
	a.closeOnce.Do(func() {
		a.listener.Close()
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, entry := range a.conns {
			entry.conn.Close()
		}
		a.conns = make(map[string]*loopbackUDPConnection)
	})
}
