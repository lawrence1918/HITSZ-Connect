package mobile

// This file exposes the aTrust/HITSZ data plane to gomobile.  The Android UI
// owns the VPN permission and TUN file descriptor; the Go package owns the
// authentication state machine and packet tunnel.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	atrust "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack/tun"
)

const (
	HITSZStateIdle           = "idle"
	HITSZStateAuthenticating = "authenticating"
	HITSZStateWaitingMFA     = "waiting_mfa"
	HITSZStateConnected      = "connected"
	HITSZStateStopping       = "stopping"
	HITSZStateError          = "error"
)

type hitszRuntime struct {
	mu         sync.RWMutex
	client     *atrust.Client
	state      string
	lastErr    string
	mfa        chan string
	stop       chan struct{}
	authData   []byte
	stack      *tun.Stack
	generation uint64
}

var hitsz = &hitszRuntime{state: HITSZStateIdle}

// ConnectHitsz starts authentication asynchronously. For app and sms MFA,
// SubmitHitszMFACode unblocks the login when the server requests a code. The
// otp method generates codes locally from mfaOTPSecret.
func ConnectHitsz(server string, port int, username, password, phone, loginDomain, mfaMethod, mfaOTPSecret, clientDataBase64 string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		server = "trust.hitsz.edu.cn"
	}
	if port == 0 {
		port = 443
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return errors.New("HITSZ username and password are required")
	}
	if loginDomain == "" {
		loginDomain = "hitcas"
	}
	mfaMethod = strings.ToLower(strings.TrimSpace(mfaMethod))
	if mfaMethod != "app" && mfaMethod != "sms" && mfaMethod != "otp" {
		return fmt.Errorf("unsupported HITSZ MFA method %q", mfaMethod)
	}
	if mfaMethod == "otp" && strings.TrimSpace(mfaOTPSecret) == "" {
		return errors.New("HITSZ OTP seed is required")
	}

	hitsz.mu.Lock()
	if hitsz.state == HITSZStateAuthenticating || hitsz.state == HITSZStateWaitingMFA || hitsz.state == HITSZStateConnected {
		hitsz.mu.Unlock()
		return errors.New("HITSZ connection is already running")
	}
	hitsz.state, hitsz.lastErr = HITSZStateAuthenticating, ""
	hitsz.generation++
	runID := hitsz.generation
	hitsz.mfa = make(chan string, 1)
	hitsz.stop = make(chan struct{})
	var authData []byte
	if clientDataBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(clientDataBase64)
		if err != nil {
			hitsz.state, hitsz.lastErr = HITSZStateError, fmt.Sprintf("decode HITSZ client data: %v", err)
			hitsz.mu.Unlock()
			return fmt.Errorf("decode HITSZ client data: %w", err)
		}
		authData = decoded
	}
	hitsz.mu.Unlock()

	go func() {
		log.Init()
		restore := auth.SetHITSZMFACodeProvider(func(method string) (string, error) {
			hitsz.mu.Lock()
			hitsz.state = HITSZStateWaitingMFA
			mfa, stop := hitsz.mfa, hitsz.stop
			hitsz.mu.Unlock()
			select {
			case code := <-mfa:
				return code, nil
			case <-stop:
				return "", errors.New("HITSZ connection stopped")
			}
		})
		defer restore()

		client := atrust.NewClient(username, "", "", "")
		// The Android VpnService excludes this application from its own VPN, so
		// aTrust underlay sockets continue to use normal system routing.
		updated, err := client.Setup(server, port, username, password, phone, loginDomain, "auth/hitsz-sso", "", "", "", mfaMethod, "", mfaOTPSecret, "", true, true, true, authData, nil, 300, "", false)
		if err != nil {
			client.Close()
			hitsz.mu.Lock()
			if hitsz.generation == runID {
				hitsz.state, hitsz.lastErr = HITSZStateError, err.Error()
			}
			hitsz.mu.Unlock()
			return
		}
		hitsz.mu.Lock()
		if hitsz.generation != runID || hitsz.state == HITSZStateStopping {
			hitsz.mu.Unlock()
			client.Close()
			return
		}
		hitsz.client, hitsz.authData = client, updated
		hitsz.state = HITSZStateConnected
		hitsz.mu.Unlock()
	}()
	return nil
}

// SubmitHitszMFACode supplies the App or SMS dynamic code requested by login.
func SubmitHitszMFACode(code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("MFA code is empty")
	}
	hitsz.mu.RLock()
	mfa, state := hitsz.mfa, hitsz.state
	hitsz.mu.RUnlock()
	if state != HITSZStateWaitingMFA || mfa == nil {
		return errors.New("HITSZ is not waiting for an MFA code")
	}
	select {
	case mfa <- code:
		return nil
	default:
		return errors.New("an MFA code is already pending")
	}
}

// HitszState returns a stable state string suitable for polling from Android.
func HitszState() string {
	hitsz.mu.RLock()
	defer hitsz.mu.RUnlock()
	return hitsz.state
}

// HitszLastError returns the redacted, user-facing error from the last run.
func HitszLastError() string {
	hitsz.mu.RLock()
	defer hitsz.mu.RUnlock()
	return hitsz.lastErr
}

// HitszClientData returns the refreshed aTrust cookie/device state as Base64.
func HitszClientData() string {
	hitsz.mu.RLock()
	defer hitsz.mu.RUnlock()
	if len(hitsz.authData) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(hitsz.authData)
}

// HitszClientIP returns the IPv4 address assigned by aTrust. Android must use
// this address on its TUN interface because it is included in L3 tunnel auth.
func HitszClientIP() (string, error) {
	hitsz.mu.RLock()
	client := hitsz.client
	hitsz.mu.RUnlock()
	if client == nil {
		return "", errors.New("HITSZ is not connected")
	}
	ip, err := client.IP()
	if err != nil {
		return "", fmt.Errorf("get HITSZ client IP: %w", err)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", fmt.Errorf("HITSZ client IP is not IPv4: %s", ip)
	}
	return ipv4.String(), nil
}

// StartHitszTun attaches the Android VpnService TUN descriptor to the current
// aTrust L3 tunnel. The descriptor is duplicated by os.NewFile and is owned by
// the Go stack for the duration of the connection.
func StartHitszTun(fd int) error {
	hitsz.mu.Lock()
	client := hitsz.client
	if client == nil || hitsz.state != HITSZStateConnected {
		hitsz.mu.Unlock()
		return errors.New("HITSZ is not connected")
	}
	stack, err := tun.NewStack(client)
	if err != nil {
		hitsz.mu.Unlock()
		return err
	}
	stack.SetupTun(fd)
	hitsz.stack = stack
	runID := hitsz.generation
	hitsz.mu.Unlock()
	go func() {
		if err := stack.Run(); err != nil {
			hitsz.mu.Lock()
			if hitsz.generation == runID && hitsz.state == HITSZStateConnected {
				hitsz.state = HITSZStateError
				hitsz.lastErr = fmt.Sprintf("HITSZ tunnel stopped: %v", err)
			}
			hitsz.mu.Unlock()
		}
	}()
	return nil
}

// Logout closes both authentication and packet tunnel state.
func LogoutHitsz() {
	hitsz.mu.Lock()
	hitsz.state = HITSZStateStopping
	hitsz.generation++
	client := hitsz.client
	stop := hitsz.stop
	hitsz.client, hitsz.stack, hitsz.mfa, hitsz.stop = nil, nil, nil, nil
	hitsz.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if client != nil {
		client.Close()
	}
	hitsz.mu.Lock()
	hitsz.state = HITSZStateIdle
	hitsz.mu.Unlock()
}

// HitszResourceSummary exposes a small diagnostic for the Android status UI.
func HitszResourceSummary() string {
	hitsz.mu.RLock()
	defer hitsz.mu.RUnlock()
	if hitsz.client == nil {
		return ""
	}
	ip, _ := hitsz.client.IP()
	domains, _ := hitsz.client.DomainResources()
	return fmt.Sprintf("IP %s; %d domain resources", ip.String(), len(domains))
}

// HitszRoutes returns the server-authorized IPv4 prefixes for VpnService.
// Android uses these routes as a system-wide split tunnel, leaving ordinary
// Internet traffic on the device's normal network.
func HitszRoutes() string {
	hitsz.mu.RLock()
	defer hitsz.mu.RUnlock()
	if hitsz.client == nil {
		return ""
	}
	ipSet, err := hitsz.client.IPSet()
	if err != nil || ipSet == nil {
		return ""
	}
	routes := make([]string, 0, len(ipSet.Prefixes()))
	for _, prefix := range ipSet.Prefixes() {
		if prefix.IP().Is4() {
			routes = append(routes, prefix.String())
		}
	}
	return strings.Join(routes, ",")
}

// ValidateHITSZClientData is intentionally small but useful to Android before
// writing restored state to preferences. It rejects arbitrary JSON blobs.
func ValidateHitszClientData(encoded string) bool {
	if encoded == "" {
		return true
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var data auth.ClientAuthData
	return json.Unmarshal(b, &data) == nil
}
