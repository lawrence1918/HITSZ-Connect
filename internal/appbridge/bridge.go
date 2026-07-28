// Package appbridge implements the newline-delimited JSON protocol used by
// the desktop application. Secrets arrive over stdin and are never required
// in process arguments.
package appbridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/configs"
)

const maxCommandSize = 4 << 20

var ErrStopped = errors.New("app bridge stopped")

// StartRequest is the validated first command received by a bridge process.
type StartRequest struct {
	RequestID          string
	Config             configs.Config
	ClientData         []byte
	ClientDataProvided bool
}

// PrepareRuntimeConfig removes options which must never be sourced from a GUI
// bridge request. Credentials and reusable session data stay in memory, while
// the App owns encrypted persistence and Shadowrocket lifecycle.
func PrepareRuntimeConfig(config *configs.Config) {
	config.ClientDataFile = ""
	config.MFAOTPSecretFile = ""
	config.ResourceFile = ""
	config.MFACode = ""
	config.CasTicket = ""
	config.OAuth2Code = ""
	config.SID = ""
	config.DeviceID = ""
	config.SignKey = ""
	config.GraphCodeFile = ""

	// The App uses scutil to control Shadowrocket's NetworkExtension service
	// without launching or foregrounding its window. The Go bridge must never
	// perform a second URL-scheme action for the same connection.
	config.Shadowrocket = "off"
	config.ShadowrocketUpdateSubs = false
	config.ShadowrocketAddNodeFile = ""
	config.ShadowrocketDisconnectOnExit = false

	// stdin belongs to the bridge dispatcher. MFA codes arrive as explicit
	// mfaCode commands rather than terminal prompts.
	config.NonInteractive = true
	config.DebugDump = false
}

// ListenerStatus reports whether the application-facing listeners are ready.
type ListenerStatus struct {
	Ready    bool `json:"ready"`
	Socks    bool `json:"socks"`
	HTTP     bool `json:"http"`
	DNSRelay bool `json:"dnsRelay"`
}

// ATrustStatus is included in ready and periodic status events.
type ATrustStatus struct {
	Connected        bool    `json:"connected"`
	RXBytes          uint64  `json:"rxBytes"`
	TXBytes          uint64  `json:"txBytes"`
	RXBytesPerSecond float64 `json:"rxBytesPerSecond"`
	TXBytesPerSecond float64 `json:"txBytesPerSecond"`
}

// Event is the stable stdout protocol. Empty fields are omitted so older GUI
// clients can safely ignore fields added by newer bridge versions.
type Event struct {
	Type       string          `json:"type"`
	RequestID  string          `json:"requestId,omitempty"`
	State      string          `json:"state,omitempty"`
	Phase      string          `json:"phase,omitempty"`
	Message    string          `json:"message,omitempty"`
	Error      string          `json:"error,omitempty"`
	Method     string          `json:"method,omitempty"`
	ClientData string          `json:"clientData,omitempty"`
	ATrust     *ATrustStatus   `json:"atrust,omitempty"`
	Listeners  *ListenerStatus `json:"listeners,omitempty"`
}

type wireCommand struct {
	Type       string          `json:"type"`
	Action     string          `json:"action"`
	Command    string          `json:"command"`
	RequestID  string          `json:"requestId"`
	Config     json.RawMessage `json:"config"`
	ClientData string          `json:"clientData"`
	Code       string          `json:"code"`
}

func (c wireCommand) commandType() string {
	for _, candidate := range []string{c.Type, c.Action, c.Command} {
		if candidate = strings.ToLower(strings.TrimSpace(candidate)); candidate != "" {
			return candidate
		}
	}
	return ""
}

type mfaCode struct {
	requestID string
	code      string
}

// Session owns stdin command dispatch and serialized stdout events.
type Session struct {
	scanner *bufio.Scanner
	encoder *json.Encoder

	emitMu     sync.Mutex
	requestID  string
	stopCh     chan struct{}
	stopOnce   sync.Once
	mfaCodes   chan mfaCode
	listenOnce sync.Once
}

func New(input io.Reader, output io.Writer) *Session {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxCommandSize)
	return &Session{
		scanner:  scanner,
		encoder:  json.NewEncoder(output),
		stopCh:   make(chan struct{}),
		mfaCodes: make(chan mfaCode, 4),
	}
}

// ReadStart reads exactly the first NDJSON command and overlays its config on
// base, preserving the CLI defaults established by flag registration.
func (s *Session) ReadStart(base configs.Config) (StartRequest, error) {
	cmd, err := s.scanCommand()
	if err != nil {
		return StartRequest{}, err
	}
	commandType := cmd.commandType()
	if commandType != "start" && commandType != "connect" {
		return StartRequest{}, fmt.Errorf("first bridge command must be start or connect")
	}
	if len(cmd.Config) == 0 || string(cmd.Config) == "null" {
		return StartRequest{}, errors.New("start command requires config")
	}

	config, embeddedClientData, embeddedProvided, err := overlayConfig(base, cmd.Config)
	if err != nil {
		return StartRequest{}, fmt.Errorf("decode bridge config: %w", err)
	}
	encodedClientData := strings.TrimSpace(cmd.ClientData)
	provided := encodedClientData != ""
	if !provided && embeddedProvided {
		encodedClientData = embeddedClientData
		provided = true
	}
	var clientData []byte
	if provided {
		clientData, err = decodeBase64(encodedClientData)
		if err != nil {
			return StartRequest{}, fmt.Errorf("decode clientData: %w", err)
		}
	}

	s.requestID = strings.TrimSpace(cmd.RequestID)
	return StartRequest{
		RequestID:          s.requestID,
		Config:             config,
		ClientData:         clientData,
		ClientDataProvided: provided,
	}, nil
}

// StartCommandLoop begins consuming mfaCode and stop/disconnect commands.
func (s *Session) StartCommandLoop() {
	s.listenOnce.Do(func() { go s.commandLoop() })
}

func (s *Session) StopChan() <-chan struct{} { return s.stopCh }

func (s *Session) RequestStop() { s.stopOnce.Do(func() { close(s.stopCh) }) }

// RequestMFACode emits mfaRequired and blocks until the GUI responds or stops.
func (s *Session) RequestMFACode(method string) (string, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if err := s.Emit(Event{
		Type:    "mfaRequired",
		State:   "waitingForMFA",
		Method:  method,
		Message: fmt.Sprintf("HITSZ %s verification code required", method),
	}); err != nil {
		return "", err
	}
	for {
		select {
		case <-s.stopCh:
			return "", ErrStopped
		case response := <-s.mfaCodes:
			if response.requestID != "" && s.requestID != "" && response.requestID != s.requestID {
				continue
			}
			code := strings.TrimSpace(response.code)
			if code == "" {
				return "", errors.New("empty MFA code")
			}
			return code, nil
		}
	}
}

func (s *Session) commandLoop() {
	defer s.RequestStop()
	for {
		cmd, err := s.scanCommand()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_ = s.EmitError(err)
			}
			return
		}
		switch cmd.commandType() {
		case "stop", "disconnect":
			return
		case "mfacode", "mfa_code":
			select {
			case s.mfaCodes <- mfaCode{requestID: strings.TrimSpace(cmd.RequestID), code: cmd.Code}:
			case <-s.stopCh:
				return
			}
		default:
			_ = s.EmitError(fmt.Errorf("unsupported bridge command %q", cmd.commandType()))
		}
	}
}

func (s *Session) scanCommand() (wireCommand, error) {
	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return wireCommand{}, err
		}
		return wireCommand{}, io.EOF
	}
	var cmd wireCommand
	if err := json.Unmarshal(s.scanner.Bytes(), &cmd); err != nil {
		return wireCommand{}, fmt.Errorf("invalid bridge JSON: %w", err)
	}
	return cmd, nil
}

func (s *Session) Emit(event Event) error {
	if event.RequestID == "" {
		event.RequestID = s.requestID
	}
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	return s.encoder.Encode(event)
}

func (s *Session) EmitPhase(phase, message string) error {
	return s.Emit(Event{Type: "phase", State: phase, Phase: phase, Message: message})
}

func (s *Session) EmitClientData(data []byte) error {
	return s.Emit(Event{Type: "clientData", ClientData: base64.StdEncoding.EncodeToString(data)})
}

func (s *Session) EmitError(err error) error {
	if err == nil {
		return nil
	}
	return s.Emit(Event{Type: "error", State: "error", Message: err.Error(), Error: err.Error()})
}

func (s *Session) EmitStopped(message string) error {
	return s.Emit(Event{Type: "stopped", State: "stopped", Message: message})
}

// WaitForTCPReady verifies an asynchronously started loopback TCP listener.
func WaitForTCPReady(ctx context.Context, address string) error {
	if strings.TrimSpace(address) == "" {
		return nil
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("listener %s not ready: %w", address, ctx.Err())
		case <-ticker.C:
		}
	}
}

func overlayConfig(base configs.Config, raw json.RawMessage) (configs.Config, string, bool, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return configs.Config{}, "", false, err
	}

	config := base
	configValue := reflect.ValueOf(&config).Elem()
	configType := configValue.Type()
	fields := make(map[string]int, configType.NumField())
	for i := 0; i < configType.NumField(); i++ {
		fields[normalizeKey(configType.Field(i).Name)] = i
	}
	aliases := map[string]string{
		"server":         "serveraddress",
		"port":           "serverport",
		"otpsecret":      "mfaotpsecret",
		"mfasecret":      "mfaotpsecret",
		"portforwarding": "portforwardinglist",
		"customdns":      "customdnslist",
	}

	clientData := ""
	clientDataProvided := false
	for key, value := range values {
		normalized := normalizeKey(key)
		if normalized == "clientdata" || normalized == "clientdatabase64" {
			if string(value) != "null" {
				if err := json.Unmarshal(value, &clientData); err != nil {
					return configs.Config{}, "", false, fmt.Errorf("%s: %w", key, err)
				}
				clientDataProvided = true
			}
			continue
		}
		if alias, ok := aliases[normalized]; ok {
			normalized = alias
		}
		index, ok := fields[normalized]
		if !ok {
			continue
		}
		field := configValue.Field(index)
		if normalized == "shadowrocket" {
			var enabled bool
			if err := json.Unmarshal(value, &enabled); err == nil {
				if enabled {
					field.SetString("connect")
				} else {
					field.SetString("off")
				}
				continue
			}
		}
		if err := setJSONField(field, value); err != nil {
			return configs.Config{}, "", false, fmt.Errorf("%s: %w", key, err)
		}
	}
	return config, clientData, clientDataProvided, nil
}

func setJSONField(field reflect.Value, raw json.RawMessage) error {
	target := reflect.New(field.Type())
	if err := json.Unmarshal(raw, target.Interface()); err == nil {
		field.Set(target.Elem())
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("invalid %s value", field.Kind())
	}
	switch field.Kind() {
	case reflect.String:
		field.SetString(text)
	case reflect.Bool:
		value, err := strconv.ParseBool(text)
		if err != nil {
			return err
		}
		field.SetBool(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(value)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return err
		}
		field.SetUint(value)
	default:
		return fmt.Errorf("invalid %s value", field.Kind())
	}
	return nil
}

func normalizeKey(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
}

func decodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 data")
}
