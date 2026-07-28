package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHITSZSliderChallengeAndVerificationUseSameSession(t *testing.T) {
	const secureKey = "0123456789ABCDEF"
	smallImage := base64.StdEncoding.EncodeToString(append([]byte("synthetic-png-data"), []byte(secureKey)...))
	challengeCalls := 0
	verifyCalls := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/common/openSliderCaptcha.htl":
			challengeCalls++
			if r.Header.Get("User-Agent") != hitszSSOUserAgent || r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
				t.Errorf("slider challenge lost browser headers")
			}
			_ = json.NewEncoder(w).Encode(hitszSliderChallenge{
				BigImage: base64.StdEncoding.EncodeToString([]byte("synthetic-background")), SmallImage: smallImage,
			})
		case "/authserver/common/verifySliderCaptcha.htl":
			verifyCalls++
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse verification form: %v", err)
			}
			sign := r.Form.Get("sign")
			if sign == "" || strings.Contains(sign, "canvasLength") {
				t.Errorf("slider answer was not encrypted")
			}
			if r.Header.Get("Origin") != server.URL || r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
				t.Errorf("slider verification lost browser headers")
			}
			_, _ = w.Write([]byte(`{"errorCode":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	session := &Session{client: server.Client()}
	loginURL := server.URL + "/authserver/login?service=synthetic"
	challenge, key, err := session.hitszOpenSliderChallenge(server.URL, loginURL)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.SmallImage != smallImage || key != secureKey {
		t.Fatalf("challenge key=%q small image preserved=%t", key, challenge.SmallImage == smallImage)
	}
	verified, err := session.hitszVerifySlider(server.URL, loginURL, key, hitszSliderAnswer{
		CanvasLength: 280,
		MoveLength:   137,
		Tracks: []hitszSliderTrack{
			{A: 0, B: 0, C: 0},
			{A: 62, B: 1, C: 45},
			{A: 137, B: 0, C: 51},
		},
	})
	if err != nil || !verified {
		t.Fatalf("slider verification verified=%t err=%v", verified, err)
	}
	if challengeCalls != 1 || verifyCalls != 1 {
		t.Fatalf("challenge calls=%d verify calls=%d", challengeCalls, verifyCalls)
	}
}

func TestHITSZSliderRejectsMalformedLocalAnswer(t *testing.T) {
	session := &Session{}
	for _, answer := range []hitszSliderAnswer{
		{CanvasLength: 279, MoveLength: 100, Tracks: []hitszSliderTrack{{}, {A: 100}}},
		{CanvasLength: 280, MoveLength: 0, Tracks: []hitszSliderTrack{{}, {}}},
		{CanvasLength: 280, MoveLength: 100, Tracks: []hitszSliderTrack{{}}},
	} {
		if _, err := session.hitszVerifySlider("https://synthetic.invalid", "https://synthetic.invalid/login", "0123456789ABCDEF", answer); err == nil {
			t.Fatalf("malformed slider answer was accepted: %#v", answer)
		}
	}
}

func TestHITSZSliderLocalBrowserRoundTrip(t *testing.T) {
	const secureKey = "0123456789ABCDEF"
	smallImage := base64.StdEncoding.EncodeToString(append([]byte("synthetic-png-data"), []byte(secureKey)...))
	var idp *httptest.Server
	idp = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/common/openSliderCaptcha.htl":
			_ = json.NewEncoder(w).Encode(hitszSliderChallenge{
				BigImage: base64.StdEncoding.EncodeToString([]byte("synthetic-background")), SmallImage: smallImage,
			})
		case "/authserver/common/verifySliderCaptcha.htl":
			if err := r.ParseForm(); err != nil || r.Form.Get("sign") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"errorCode":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idp.Close()

	browserResult := make(chan error, 1)
	session := &Session{
		client:             idp.Client(),
		hitszSliderTimeout: 5 * time.Second,
		hitszSliderBrowserOpener: func(localURL string) {
			go func() {
				page, err := http.Get(localURL)
				if err != nil {
					browserResult <- err
					return
				}
				pageBody, _ := io.ReadAll(page.Body)
				_ = page.Body.Close()
				if page.StatusCode != http.StatusOK || !bytes.Contains(pageBody, []byte("统一认证安全验证")) {
					browserResult <- fmt.Errorf("unexpected local slider page")
					return
				}
				challenge, err := http.Get(localURL + "challenge")
				if err != nil {
					browserResult <- err
					return
				}
				_ = challenge.Body.Close()
				if challenge.StatusCode != http.StatusOK {
					browserResult <- fmt.Errorf("local challenge status %s", challenge.Status)
					return
				}
				answer, _ := json.Marshal(hitszSliderAnswer{
					CanvasLength: 280, MoveLength: 137,
					Tracks: []hitszSliderTrack{{A: 0, B: 0, C: 0}, {A: 137, B: 0, C: 50}},
				})
				verify, err := http.Post(localURL+"verify", "application/json", bytes.NewReader(answer))
				if err != nil {
					browserResult <- err
					return
				}
				defer verify.Body.Close()
				if verify.StatusCode != http.StatusOK {
					browserResult <- fmt.Errorf("local verification status %s", verify.Status)
					return
				}
				var result map[string]bool
				if err := json.NewDecoder(verify.Body).Decode(&result); err != nil || !result["ok"] {
					browserResult <- fmt.Errorf("local verification result=%v err=%v", result, err)
					return
				}
				browserResult <- nil
			}()
		},
	}
	if err := session.hitszSolveSliderCaptcha(idp.URL, idp.URL+"/authserver/login?service=synthetic"); err != nil {
		t.Fatal(err)
	}
	if err := <-browserResult; err != nil {
		t.Fatal(err)
	}
}
