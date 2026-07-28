package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseHITSZLoginFormAndMFATabs(t *testing.T) {
	page := []byte(`<html>
		<form id="qrLoginForm"><input type="hidden" name="uuid" value="trap"><input type="hidden" name="execution" value="wrong-before"></form>
		<form id="pwdFromId">
			<input type="text" name="username" value="trap-user">
			<input type="password" name="passwordText" value="trap-password">
			<input type="hidden" name="cllt" value="userNameLogin">
			<input type="hidden" name="execution" value="e2s1">
			<input id="pwdEncryptSalt" type="hidden" value="whBSMLc9WmoD31SN">
		</form>
		<form id="phoneFromId"><input type="hidden" name="dynamicCode" value="trap"><input type="hidden" name="execution" value="wrong-after"></form>
		<div id="tab_13" data-type="13"></div><div id="tab_3" data-type="3"></div>
	</html>`)
	values, salt, err := parseHITSZLoginForm(page)
	if err != nil || salt != "whBSMLc9WmoD31SN" || values.Get("execution") != "e2s1" || values.Get("cllt") != "userNameLogin" {
		t.Fatalf("unexpected parsed HITSZ form: values=%v salt=%q err=%v", values, salt, err)
	}
	for _, trap := range []string{"uuid", "username", "passwordText", "dynamicCode"} {
		if _, ok := values[trap]; ok {
			t.Fatalf("password form parser retained unrelated field %q", trap)
		}
	}
	methods := parseHITSZMFAMethods(page)
	if len(methods) != 2 || methods[0].name != hitszMFAApp || methods[1].name != hitszMFASMS {
		t.Fatalf("unexpected MFA methods: %#v", methods)
	}
}

func TestHITSZCredentialLoginStopsBeforeRequiredSliderInNonInteractiveMode(t *testing.T) {
	postedCredentials := false
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/login":
			if r.Method == http.MethodPost {
				postedCredentials = true
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`<form id="pwdFromId"><input type="hidden" name="execution" value="e1s1"><input id="pwdEncryptSalt" type="hidden" value="whBSMLc9WmoD31SN"></form>`))
		case "/authserver/bfp/info":
			http.SetCookie(w, &http.Cookie{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: "synthetic", Path: "/"})
			_, _ = w.Write([]byte(`{}`))
		case "/authserver/checkNeedCaptcha.htl":
			if got := r.URL.Query().Get("username"); got != "synthetic-student" {
				t.Errorf("CAPTCHA preflight username=%q", got)
			}
			if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
				t.Errorf("CAPTCHA preflight X-Requested-With=%q", got)
			}
			_, _ = w.Write([]byte(`{"isNeed":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	session := &Session{client: client}
	service := server.URL + "/service"
	_, err = session.hitszCredentialLogin(
		server.URL+"/authserver/login?service="+url.QueryEscape(service),
		server.URL,
		service,
		HITSZSSOLogin{Username: "synthetic-student", Password: "synthetic-password", NonInteractive: true},
	)
	if !errors.Is(err, ErrHITSZCaptchaRequired) {
		t.Fatalf("credential login error = %v, want ErrHITSZCaptchaRequired", err)
	}
	if postedCredentials {
		t.Fatal("credential POST was sent despite required browser CAPTCHA")
	}
}

func TestHITSZCredentialLoginCompletesRequiredSliderBeforePosting(t *testing.T) {
	postedCredentials := false
	sliderCalls := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form id="pwdFromId">
					<input type="hidden" name="execution" value="e1s1">
					<input type="hidden" name="pwdEncryptSalt" value="whBSMLc9WmoD31SN">
				</form>`))
				return
			}
			postedCredentials = true
			http.Redirect(w, r, server.URL+"/service?ticket=ST-synthetic", http.StatusFound)
		case "/authserver/bfp/info":
			http.SetCookie(w, &http.Cookie{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: "synthetic", Path: "/"})
			_, _ = w.Write([]byte(`{}`))
		case "/authserver/checkNeedCaptcha.htl":
			_, _ = w.Write([]byte(`{"isNeed":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	service := server.URL + "/service"
	loginURL := server.URL + "/authserver/login?service=" + url.QueryEscape(service)
	session := &Session{
		client: client,
		hitszSliderCaptchaSolver: func(origin, gotLoginURL string) error {
			sliderCalls++
			if origin != server.URL || gotLoginURL != loginURL {
				t.Errorf("slider solver origin=%q loginURL=%q", origin, gotLoginURL)
			}
			return nil
		},
	}
	callback, err := session.hitszCredentialLogin(loginURL, server.URL, service, HITSZSSOLogin{
		Username: "synthetic-student", Password: "synthetic-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sliderCalls != 1 || !postedCredentials {
		t.Fatalf("slider calls=%d posted=%t", sliderCalls, postedCredentials)
	}
	if callback != server.URL+"/service?ticket=ST-synthetic" {
		t.Fatalf("callback=%q", callback)
	}
}

func TestHITSZCredentialLoginBuildsScopedBrowserRequest(t *testing.T) {
	postedCredentials := false
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form id="qrLoginForm"><input type="hidden" name="uuid" value="trap"></form>
					<form id="pwdFromId">
					<input type="text" name="username" value="trap-user">
					<input type="password" name="passwordText" value="trap-password">
					<input type="hidden" name="_eventId" value="submit">
					<input type="hidden" name="cllt" value="userNameLogin">
					<input type="hidden" name="dllt" value="generalLogin">
					<input type="hidden" name="execution" value="e1s1">
					<input type="hidden" name="password" value="">
					<input type="hidden" name="pwdEncryptSalt" value="whBSMLc9WmoD31SN">
					</form>`))
				return
			}
			postedCredentials = true
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse credential form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for key, want := range map[string]string{
				"username": "synthetic-student", "_eventId": "submit", "cllt": "userNameLogin",
				"dllt": "generalLogin", "execution": "e1s1", "captcha": "", "rememberMe": "true",
			} {
				if got := r.Form.Get(key); got != want {
					t.Errorf("credential form %s=%q, want %q", key, got, want)
				}
			}
			if encrypted := r.Form.Get("password"); encrypted == "" || encrypted == "synthetic-password" {
				t.Error("password was not encrypted")
			}
			for _, trap := range []string{"uuid", "passwordText"} {
				if _, ok := r.Form[trap]; ok {
					t.Errorf("credential form retained unrelated field %q", trap)
				}
			}
			if got := r.Header.Get("Origin"); got != server.URL {
				t.Errorf("Origin=%q", got)
			}
			if got := r.Header.Get("Referer"); !strings.HasPrefix(got, server.URL+"/authserver/login?service=") {
				t.Errorf("Referer=%q", got)
			}
			if got := r.Header.Get("User-Agent"); got != hitszSSOUserAgent {
				t.Errorf("User-Agent=%q", got)
			}
			if cookie, err := r.Cookie("MULTIFACTOR_BROWSER_FINGERPRINT"); err != nil || cookie.Value != "synthetic" {
				t.Errorf("fingerprint cookie=%v err=%v", cookie, err)
			}
			http.Redirect(w, r, server.URL+"/service?ticket=ST-synthetic", http.StatusFound)
		case "/authserver/bfp/info":
			http.SetCookie(w, &http.Cookie{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: "synthetic", Path: "/"})
			_, _ = w.Write([]byte(`{}`))
		case "/authserver/checkNeedCaptcha.htl":
			_, _ = w.Write([]byte(`{"isNeed":"false"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	session := &Session{client: client}
	service := server.URL + "/service"
	loginURL := server.URL + "/authserver/login?service=" + url.QueryEscape(service)
	callback, err := session.hitszCredentialLogin(loginURL, server.URL, service, HITSZSSOLogin{
		Username: "synthetic-student", Password: "synthetic-password", RememberSSO: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !postedCredentials || callback != server.URL+"/service?ticket=ST-synthetic" {
		t.Fatalf("posted=%t callback=%q", postedCredentials, callback)
	}
}

func TestUnexpectedHITSZLoginRedirectRedactsTicket(t *testing.T) {
	location, err := url.Parse("https://trust.hitsz.edu.cn/unexpected?ticket=ST-sensitive&username=synthetic")
	if err != nil {
		t.Fatal(err)
	}
	message := unexpectedHITSZLoginRedirect(location).Error()
	if strings.Contains(message, "ST-sensitive") || strings.Contains(message, "username") {
		t.Fatalf("redirect error leaked query: %s", message)
	}
	if !strings.Contains(message, "https://trust.hitsz.edu.cn/unexpected") {
		t.Fatalf("redirect error lost redacted location: %s", message)
	}
}

func TestHITSZSSOTransportErrorRedactsRequestQuery(t *testing.T) {
	const syntheticTicket = "ST-synthetic-transport-ticket"
	const syntheticUsername = "synthetic-transport-username"
	rawURL := "https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login?ticket=" + syntheticTicket + "&username=" + syntheticUsername
	session := &Session{client: &http.Client{Transport: casRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic transport failure for " + request.URL.String())
	})}}

	_, err := session.doNoRedirect(http.MethodGet, rawURL, nil, nil)
	if err == nil {
		t.Fatal("HITSZ SSO request unexpectedly succeeded")
	}
	if got := err.Error(); got != "HITSZ SSO request failed" {
		t.Fatalf("HITSZ SSO transport error was not sanitized: %q", got)
	}
	for _, sensitive := range []string{syntheticTicket, syntheticUsername, "ticket=", "username="} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("HITSZ SSO transport error exposed request query: %q", err)
		}
	}
}

func TestHITSZLocationParseErrorRedactsHeaderQuery(t *testing.T) {
	const syntheticTicket = "ST-synthetic-location-ticket"
	const syntheticUsername = "synthetic-location-username"
	malformedLocation := "https://trust.synthetic.example/%zz?ticket=" + syntheticTicket + "&username=" + syntheticUsername
	session := &Session{client: &http.Client{Transport: casRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Status:     "302 Found",
			Header:     http.Header{"Location": []string{malformedLocation}},
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})}}

	_, _, err := session.hitszExistingSession("https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", "https://trust.synthetic.example/service")
	if err == nil {
		t.Fatal("malformed HITSZ Location unexpectedly succeeded")
	}
	// net/http may reject the malformed Location while processing the 302,
	// before hitszExistingSession calls Response.Location itself. Both paths
	// must collapse to a query-free static error.
	if got := err.Error(); got != "HITSZ SSO request failed" && got != "HITSZ existing-session redirect has no valid location" {
		t.Fatalf("HITSZ Location parse error was not sanitized: %q", got)
	}
	for _, sensitive := range []string{syntheticTicket, syntheticUsername, "ticket=", "username="} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("HITSZ Location parse error exposed header query: %q", err)
		}
	}
}

func TestParseHITSZOTPMFAMethod(t *testing.T) {
	methods := parseHITSZMFAMethods([]byte(`<a class="reauth-tab-more-item" id="10" data-name="安全令牌OTP"></a>`))
	if len(methods) != 1 || methods[0].name != hitszMFAOTP || methods[0].reauthType != "10" {
		t.Fatalf("unexpected OTP MFA methods: %#v", methods)
	}
}

func TestGenerateHITSZTOTP(t *testing.T) {
	// RFC 6238's SHA-1 test seed at Unix time 59 produces 94287082 with
	// eight digits; HITSZ's type 10 form requires its six-digit suffix.
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, secret := range []string{
		seed,
		"otpauth://totp/HITSZ:test?secret=" + seed + "&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/test-user?secret=" + seed + "&issuer=%E6%B5%8B%E8%AF%95",
	} {
		code, err := generateHITSZTOTP(secret, time.Unix(59, 0))
		if err != nil || code != "287082" {
			t.Fatalf("code=%q err=%v", code, err)
		}
	}
	for _, secret := range []string{
		"otpauth://totp/HITSZ:test?secret=ABC&algorithm=SHA256",
		"otpauth://hotp/HITSZ:test?secret=ABC",
		"not a Base32 seed!",
	} {
		if _, err := generateHITSZTOTP(secret, time.Unix(59, 0)); err == nil {
			t.Fatalf("expected invalid secret %q to fail", secret)
		}
	}
}

func TestHITSZBrowserFingerprint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authserver/bfp/info" {
			t.Errorf("path=%s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("sf_request_type"); got != "ajax" {
			t.Errorf("sf_request_type=%q", got)
		}
		if got := r.URL.Query().Get("bfp"); len(got) != 32 || got != strings.ToUpper(got) {
			t.Errorf("unexpected redacted fingerprint shape: length=%d", len(got))
		}
		if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
			t.Errorf("X-Requested-With=%q", got)
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("fingerprint request has no user agent")
		}
		http.SetCookie(w, &http.Cookie{Name: "MULTIFACTOR_BROWSER_FINGERPRINT", Value: "test", Path: "/"})
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	session := &Session{client: client}
	if err := session.hitszBrowserFingerprint(server.URL, server.URL+"/authserver/login?service=test"); err != nil {
		t.Fatal(err)
	}
}

func TestHITSZOTPDoesNotRequestDynamicCode(t *testing.T) {
	dynamicCodeRequested := false
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/reAuthCheck/changeReAuthType.do":
			if err := r.ParseForm(); err != nil || r.Form.Get("reAuthType") != "10" {
				t.Errorf("unexpected OTP type switch: form=%v err=%v", r.Form, err)
			}
			_, _ = w.Write([]byte(`{"res":"success"}`))
		case "/authserver/dynamicCode/getDynamicCodeByReauth.do":
			dynamicCodeRequested = true
			w.WriteHeader(http.StatusInternalServerError)
		case "/authserver/systemTime":
			if got := r.URL.Query().Get("sf_request_type"); got != "ajax" {
				t.Errorf("systemTime missing ajax query flag: %q", got)
			}
			if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
				t.Errorf("systemTime missing XHR header: %q", got)
			}
			_, _ = w.Write([]byte(`{"systemTime":"2026-07-27 14:00:00"}`))
		case "/authserver/reAuthCheck/reAuthSubmit.do":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse OTP submit form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("otpCode"); len(got) != 6 || strings.Trim(got, "0123456789") != "" {
				t.Errorf("unexpected OTP value shape: %q", got)
			}
			if got := r.Form.Get("dynamicCode"); got != "" {
				t.Errorf("dynamicCode=%q; OTP must use otpCode", got)
			}
			if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
				t.Errorf("OTP submit did not use browser XHR: %q", got)
			}
			if got := r.URL.Query().Get("sf_request_type"); got != "ajax" {
				t.Errorf("OTP submit missing ajax query flag: %q", got)
			}
			_, _ = w.Write([]byte(`{"code":"reAuth_success"}`))
		case "/authserver/login":
			http.Redirect(w, r, server.URL+"/service?ticket=ST-otp", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	session := &Session{client: server.Client()}
	callback, err := session.hitszCompleteMFA(server.URL, server.URL+"/service", HITSZSSOLogin{
		Username: "test-user", MFAMethod: hitszMFAOTP, MFAOTPSecret: "JBSWY3DPEHPK3PXP", NonInteractive: true,
	}, server.URL+"/authserver/reAuthCheck/reAuthLoginView.do", []byte(`<div id="tab_10" data-type="10"></div>`))
	if err != nil {
		t.Fatal(err)
	}
	if callback != server.URL+"/service?ticket=ST-otp" {
		t.Fatalf("callback=%q", callback)
	}
	if dynamicCodeRequested {
		t.Fatal("OTP flow called getDynamicCodeByReauth")
	}
}

func TestDoUntilHITSZServiceFollowsInternalRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.Redirect(w, r, "/internal", http.StatusFound)
		case "/internal":
			http.Redirect(w, r, "/service?ticket=one", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	session := &Session{client: server.Client()}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := session.doUntilHITSZService(req, server.URL+"/service")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%s", resp.Status)
	}
	location, err := resp.Location()
	if err != nil || !isHITSZServiceCallback(location.String(), server.URL+"/service") {
		t.Fatalf("unexpected callback %v, err=%v", location, err)
	}
}

func TestIsHITSZServiceCallback(t *testing.T) {
	service := "https://trust.hitsz.edu.cn:443/passport/v1/auth/cas?sfDomain=hitcas"
	for _, callback := range []string{
		"https://trust.hitsz.edu.cn/passport/v1/auth/cas?sfDomain=hitcas&ticket=ST-1",
		"https://trust.hitsz.edu.cn:443/passport/v1/auth/cas?ticket=ST-1&sfDomain=hitcas",
		"https://TRUST.HITSZ.EDU.CN/passport/v1/auth/cas?sfDomain=hitcas&ticket=ST-1",
	} {
		if !isHITSZServiceCallback(callback, service) {
			t.Fatalf("expected callback to match: %s", callback)
		}
	}

	for _, callback := range []string{
		"https://trust.hitsz.edu.cn.evil/passport/v1/auth/cas?sfDomain=hitcas&ticket=ST-1",
		"https://trust.hitsz.edu.cn/passport/v1/auth/cas/extra?sfDomain=hitcas&ticket=ST-1",
		"https://trust.hitsz.edu.cn/passport/v1/auth/cas?sfDomain=other&ticket=ST-1",
		"https://trust.hitsz.edu.cn/passport/v1/auth/cas?sfDomain=hitcas",
		"https://trust.hitsz.edu.cn:443.evil/passport/v1/auth/cas?sfDomain=hitcas&ticket=ST-1",
	} {
		if isHITSZServiceCallback(callback, service) {
			t.Fatalf("expected callback not to match: %s", callback)
		}
	}
}

func TestParseLegacyHITSZMFAType(t *testing.T) {
	page := []byte(`<div class="changeReAuthTypes active" id="3"></div>`)
	methods := parseHITSZMFAMethods(page)
	if len(methods) != 1 || methods[0].name != hitszMFASMS {
		t.Fatalf("unexpected legacy MFA methods: %#v", methods)
	}
	if !isHITSZMFAPage(page) {
		t.Fatal("legacy changeReAuthTypes page was not recognized as MFA")
	}
	if methods := parseHITSZMFAMethods([]byte(`<div class="notchangeReAuthTypes" id="3"></div>`)); len(methods) != 0 {
		t.Fatalf("non-class substring must not enable MFA: %#v", methods)
	}
}

func TestValidateHITSZIDPRedirect(t *testing.T) {
	service := "https://trust.hitsz.edu.cn:443/passport/v1/auth/cas?sfDomain=hitcas"
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if err := validateHITSZIDPRedirect(parse("https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login"), service, "trust.hitsz.edu.cn", "hitcas"); err != nil {
		t.Fatalf("expected valid HITSZ CAS redirect: %v", err)
	}

	for _, test := range []struct {
		name    string
		idp     string
		service string
	}{
		{"non-https-idp", "http://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", service},
		{"idp-userinfo", "https://user@ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", service},
		{"unknown-idp", "https://ids-hit-edu-cn-s.hitsz.edu.cn.evil/authserver/login", service},
		{"wrong-service-host", "https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", "https://evil.example/passport/v1/auth/cas?sfDomain=hitcas"},
		{"wrong-service-path", "https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", "https://trust.hitsz.edu.cn/passport/v1/auth/other?sfDomain=hitcas"},
		{"wrong-domain", "https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", "https://trust.hitsz.edu.cn/passport/v1/auth/cas?sfDomain=other"},
		{"duplicate-domain", "https://ids-hit-edu-cn-s.hitsz.edu.cn/authserver/login", "https://trust.hitsz.edu.cn/passport/v1/auth/cas?sfDomain=hitcas&sfDomain=hitcas"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateHITSZIDPRedirect(parse(test.idp), test.service, "trust.hitsz.edu.cn", "hitcas"); err == nil {
				t.Fatal("expected redirect validation to fail")
			}
		})
	}
}

func TestHITSZLoginEnablesTLSVerificationBeforeAuthConfig(t *testing.T) {
	blockedDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial blocked by test")
	}
	session := NewSession("trust.hitsz.edu.cn", blockedDial)
	transport, ok := session.client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("NewSession legacy transport unexpectedly changed")
	}
	_, _ = session.Login(HITSZSSOLogin{Domain: "hitcas"}, LoginOptions{})
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HITSZ login did not enable certificate verification before authConfig")
	}
}

func TestEncryptHITSZPassword(t *testing.T) {
	encrypted, err := encryptHITSZPassword("secret-password", "whBSMLc9WmoD31SN")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil || len(decoded) == 0 || string(decoded) == "secret-password" {
		t.Fatalf("unexpected encrypted password %q: %v", encrypted, err)
	}
}
