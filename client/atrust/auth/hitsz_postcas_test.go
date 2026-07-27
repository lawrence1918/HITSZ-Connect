package auth

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHITSZPostCASTestSession(t *testing.T, server *httptest.Server) *Session {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	return &Session{
		client:           client,
		baseURL:          server.URL,
		baseHost:         strings.TrimPrefix(server.URL, "https://"),
		rid:              "test-rid",
		csrfToken:        "csrf-before-refresh",
		ticket:           "portal-ticket-fixture",
		hitszBrowserMode: true,
	}
}

func assertHITSZBrowserIdentity(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.URL.Query().Get("clientType"); got != "SDPBrowserClient" {
		t.Errorf("clientType=%q", got)
	}
	if got := r.URL.Query().Get("platform"); got != "Mac" {
		t.Errorf("platform=%q", got)
	}
	if got := r.URL.Query().Get("lang"); got != "zh-CN" {
		t.Errorf("lang=%q", got)
	}
	if got := r.Header.Get("User-Agent"); got != hitszSSOUserAgent {
		t.Errorf("unexpected user agent %q", got)
	}
}

func TestHITSZPostCASRefreshReportsBeforeAuthCheck(t *testing.T) {
	var sequence []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			sequence = append(sequence, "authConfig")
			assertHITSZBrowserIdentity(t, r)
			if got := r.URL.Query().Get("mod"); got != "1" {
				t.Errorf("mod=%q", got)
			}
			if got := r.URL.Query().Get("needTicket"); got != "1" {
				t.Errorf("needTicket=%q", got)
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":0,"csrfToken":"csrf-after-refresh","guid":"guid-fixture","antiMITMAttackData":{"enable":1,"ticket":"pre-login-ticket-fixture","challenge":"fixture"}}}`))
		case "/controller/v1/public/reportEnv":
			sequence = append(sequence, "reportEnv")
			assertHITSZBrowserIdentity(t, r)
			if got := r.Header.Get("X-Csrf-Token"); got != "csrf-after-refresh" {
				t.Errorf("report csrf=%q", got)
			}
			_, _ = w.Write([]byte(`{"code":0}`))
		case "/passport/v1/auth/authCheck":
			sequence = append(sequence, "authCheck")
			assertHITSZBrowserIdentity(t, r)
			if got := r.Header.Get("X-Csrf-Token"); got != "csrf-after-refresh" {
				t.Errorf("authCheck csrf=%q", got)
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"nextService":""}}`))
		case "/v1/service/reportEnvBeforeLogin":
			t.Error("HITSZ must not send the local-agent payload to the remote gateway")
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	session := newHITSZPostCASTestSession(t, server)
	if err := session.hitszPostCAS(); err != nil {
		t.Fatal(err)
	}
	if err := session.continueAuth(authStep{Service: "auth/authCheck"}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(sequence, ","), "authConfig,reportEnv,authCheck"; got != want {
		t.Fatalf("request order=%q want %q", got, want)
	}
}

func TestHITSZBrowserIdentityDoesNotChangeLegacyAuthConfig(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/public/authConfig" {
			t.Errorf("path=%s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("clientType"); got != "SDPClient" {
			t.Errorf("legacy clientType=%q", got)
		}
		if got := r.URL.Query().Get("platform"); got != "Linux" {
			t.Errorf("legacy platform=%q", got)
		}
		if got := r.URL.Query().Get("lang"); got != "en-US" {
			t.Errorf("legacy lang=%q", got)
		}
		if got := r.Header.Get("User-Agent"); got != UserAgent {
			t.Errorf("legacy user agent=%q", got)
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":0}}`))
	}))
	defer server.Close()

	session := newHITSZPostCASTestSession(t, server)
	session.hitszBrowserMode = false
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestHITSZPostCASLetsAuthCheckRunWhenReportEnvFails(t *testing.T) {
	var sequence []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			sequence = append(sequence, "authConfig")
			assertHITSZBrowserIdentity(t, r)
			_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":0,"csrfToken":"csrf-after-refresh"}}`))
		case "/controller/v1/public/reportEnv":
			sequence = append(sequence, "reportEnv")
			assertHITSZBrowserIdentity(t, r)
			// The public browser script treats this as a best-effort transition.
			_, _ = w.Write([]byte(`{"code":75510008}`))
		case "/passport/v1/auth/authCheck":
			sequence = append(sequence, "authCheck")
			assertHITSZBrowserIdentity(t, r)
			_, _ = w.Write([]byte(`{"code":0,"data":{"nextService":""}}`))
		default:
			t.Errorf("unexpected remote path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	session := newHITSZPostCASTestSession(t, server)
	if err := session.hitszPostCAS(); err != nil {
		t.Fatalf("best-effort reportEnv must not block HITSZ authCheck: %v", err)
	}
	if err := session.continueAuth(authStep{Service: "auth/authCheck"}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(sequence, ","), "authConfig,reportEnv,authCheck"; got != want {
		t.Fatalf("request order=%q want %q", got, want)
	}
}
