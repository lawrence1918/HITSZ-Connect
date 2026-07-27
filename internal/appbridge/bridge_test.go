package appbridge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/configs"
)

func TestReadStartAliasesAndClientData(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"device":"state"}`))
	input := strings.NewReader(`{"type":"connect","requestId":"req-1","config":{"profile":"hitsz","server":"vpn.example","server_port":"444","username":"u","password":"p","mfaMethod":"otp","otpSecret":"SECRET","shadowrocket":true},"clientData":"` + encoded + `"}` + "\n")
	session := New(input, &bytes.Buffer{})
	request, err := session.ReadStart(configs.Config{ServerPort: 443, Shadowrocket: "off"})
	if err != nil {
		t.Fatal(err)
	}
	if request.RequestID != "req-1" || request.Config.ServerAddress != "vpn.example" || request.Config.ServerPort != 444 {
		t.Fatalf("unexpected request: %+v", request)
	}
	if request.Config.MFAOTPSecret != "SECRET" || request.Config.Shadowrocket != "connect" {
		t.Fatalf("unexpected config: %+v", request.Config)
	}
	if !request.ClientDataProvided || string(request.ClientData) != `{"device":"state"}` {
		t.Fatalf("unexpected client data: %q", request.ClientData)
	}
}

func TestEventsAreNDJSON(t *testing.T) {
	var output bytes.Buffer
	session := New(strings.NewReader(`{"type":"start","requestId":"r","config":{}}`+"\n"), &output)
	if _, err := session.ReadStart(configs.Config{}); err != nil {
		t.Fatal(err)
	}
	if err := session.EmitPhase("authenticating", "Signing in"); err != nil {
		t.Fatal(err)
	}
	if err := session.EmitClientData([]byte("state")); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), output.String())
	}
	for _, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid event %q: %v", line, err)
		}
		if event.RequestID != "r" {
			t.Fatalf("requestId = %q", event.RequestID)
		}
	}
}

func TestRejectsNonStartFirstCommand(t *testing.T) {
	session := New(strings.NewReader(`{"type":"stop"}`+"\n"), &bytes.Buffer{})
	if _, err := session.ReadStart(configs.Config{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMFACodeAndStopCommands(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	var output bytes.Buffer
	session := New(reader, &output)

	go func() {
		_, _ = io.WriteString(writer, `{"type":"connect","requestId":"r","config":{}}`+"\n")
	}()
	if _, err := session.ReadStart(configs.Config{}); err != nil {
		t.Fatal(err)
	}
	session.StartCommandLoop()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		code, err := session.RequestMFACode("sms")
		codeCh <- code
		errCh <- err
	}()
	if _, err := io.WriteString(writer, `{"type":"mfaCode","requestId":"r","code":"123456"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-codeCh:
		if err := <-errCh; err != nil || code != "123456" {
			t.Fatalf("code = %q, err = %v", code, err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MFA code")
	}

	if _, err := io.WriteString(writer, `{"type":"disconnect"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.StopChan():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for stop")
	}
	_ = writer.Close()

	if !strings.Contains(output.String(), `"type":"mfaRequired"`) {
		t.Fatalf("missing mfaRequired event: %s", output.String())
	}
}
