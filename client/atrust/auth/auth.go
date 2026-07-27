package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const (
	UserAgent    = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
	maxAttempts  = 5
	maxAuthSteps = 8
)

var sharedParams = url.Values{
	"clientType": {"SDPClient"},
	"platform":   {"Linux"},
	"lang":       {"en-US"},
}

// hitszBrowserParams deliberately describes the browser integration that
// HITSZ exposes for its aTrust tenant.  It must remain separate from
// sharedParams: existing aTrust gateways expect the desktop-client identity.
var hitszBrowserParams = url.Values{
	"clientType": {"SDPBrowserClient"},
	"platform":   {"Mac"},
	"lang":       {"zh-CN"},
}

func WithSharedParams(extra url.Values) url.Values {
	return withBaseParams(sharedParams, extra)
}

func withBaseParams(base, extra url.Values) url.Values {
	combined := make(url.Values, len(base)+len(extra))
	for k, v := range base {
		combined[k] = append([]string(nil), v...)
	}

	for k, v := range extra {
		for _, val := range v {
			// notice: not Add()
			combined.Set(k, val)
		}
	}

	return combined
}

// requestParams and requestUserAgent only change wire identity for an
// explicitly selected HITSZ SSO login.  All historical login methods retain
// the legacy aTrust client parameters and user agent.
func (s *Session) requestParams(extra url.Values) url.Values {
	if s != nil && s.hitszBrowserMode {
		return withBaseParams(hitszBrowserParams, extra)
	}
	return WithSharedParams(extra)
}

func (s *Session) requestUserAgent() string {
	if s != nil && s.hitszBrowserMode {
		return hitszSSOUserAgent
	}
	return UserAgent
}

type Cookie struct {
	Host       string        `json:"host"`
	Scheme     string        `json:"scheme"`
	Name       string        `json:"name"`
	Value      string        `json:"value"`
	Path       string        `json:"path,omitempty"`
	Domain     string        `json:"domain,omitempty"`
	Expires    time.Time     `json:"expires,omitempty"`
	RawExpires string        `json:"raw_expires,omitempty"`
	MaxAge     int           `json:"max_age,omitempty"`
	Secure     bool          `json:"secure,omitempty"`
	HttpOnly   bool          `json:"http_only,omitempty"`
	SameSite   http.SameSite `json:"same_site,omitempty"`
}

type ClientAuthData struct {
	Cookies  []Cookie `json:"cookies"`
	DeviceID string   `json:"device_id"`
}

type Session struct {
	client   *http.Client
	deviceID string

	baseHost string
	baseURL  string

	rid            string
	env            string
	csrfToken      string
	pubKey         string
	pubKeyExp      string
	antiReplayRand string
	ticket         string

	// HITSZ uses browser-shaped headers and query parameters for aTrust HTTP
	// requests. This is transient session state and is never persisted.
	hitszBrowserMode bool

	response   map[string]json.RawMessage
	cookieURLs map[string]*url.URL
	// hitszRedirectTrace stores only redacted scheme/host/path values from the
	// final HITSZ MFA redirect chain. It is intentionally never persisted.
	hitszRedirectTrace []string
}

func NewSession(server string, dialContext ...func(context.Context, string, string) (net.Conn, error)) *Session {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if len(dialContext) > 0 && dialContext[0] != nil {
		tr.DialContext = dialContext[0]
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second}

	rid := base64.StdEncoding.EncodeToString([]byte(server))

	baseURL := &url.URL{Host: server, Scheme: "https"}
	return &Session{
		client:     client,
		baseHost:   server,
		baseURL:    "https://" + server,
		rid:        rid,
		response:   make(map[string]json.RawMessage),
		cookieURLs: map[string]*url.URL{"https://" + server: baseURL},
	}
}

// enableTLSVerification upgrades this session from the legacy aTrust TLS
// behavior to normal certificate verification.  NewSession intentionally
// keeps its historical permissive default for existing gateways, but HITSZ
// authentication sends primary credentials to a public IdP and must not reuse
// an insecure TLS connection.
func (s *Session) enableTLSVerification() {
	if s == nil || s.client == nil {
		return
	}
	transport, ok := s.client.Transport.(*http.Transport)
	if !ok || transport == nil {
		// A nil or custom RoundTripper is already outside NewSession's legacy
		// insecure transport.  Do not replace it here because callers may have
		// supplied a transport with custom root CAs or proxy behavior.
		return
	}

	config := transport.TLSClientConfig
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	config.InsecureSkipVerify = false
	transport.TLSClientConfig = config
	// A Session can be reused after GetAuthInfoList.  Closing idle connections
	// ensures the HITSZ flow cannot continue over a connection established when
	// certificate verification was disabled.
	transport.CloseIdleConnections()
}

type AuthInfo struct {
	LoginDomain string `json:"loginDomain"`
	AuthType    string `json:"authType"`
	AuthName    string `json:"authName"`
	LoginURL    string `json:"loginUrl"`
}

type LoginOptions struct {
	DeviceID string
	Cookies  []Cookie
}

type LoginResult struct {
	Username string
	SID      string
	Cookies  []Cookie
}

type LoginMethod interface {
	AuthType() string
	LoginDomain() string
	login(*Session, AuthInfo) error
}

func (s *Session) randSdpId(n ...int) string {
	length := 8
	if len(n) > 0 {
		length = n[0]
	}
	hexes := make([]byte, length)
	for i := 0; i < length; i++ {
		hexes[i] = "0123456789abcdef"[mathrand.Intn(16)]
	}
	return string(hexes)
}

func (s *Session) withGraphCheckCode(process func(string) (int, error), graphCodeFile string) error {
	graphCheckCodeEnable, err := process("")
	if err != nil {
		return err
	}

	for attempt := 1; graphCheckCodeEnable == 1 && attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("Captcha attempt %d/%d", attempt, maxAttempts)
		}

		imgData, err := s.checkCode()
		if err != nil {
			return err
		}

		_, _, err = s.authConfig(false, true)
		if err != nil {
			return err
		}

		var graphCheckCode string
		if graphCodeFile != "" {
			if writeErr := os.WriteFile(graphCodeFile, imgData, 0644); writeErr != nil {
				log.Printf("Warning: failed to write graph code image to %s: %v", graphCodeFile, writeErr)
			} else {
				log.Printf("Graph check code saved to %s", graphCodeFile)
			}

			log.Print("Please enter the graph check code JSON: ")
			_, err = fmt.Scanln(&graphCheckCode)
			if err != nil {
				return err
			}
		} else {
			graphCheckCode, err = serveCaptchaInBrowser(imgData, 5*time.Minute)
			if err != nil {
				return fmt.Errorf("failed to get captcha input: %w", err)
			}
		}

		log.DebugPrintf("graphCheckCode submitted: %s", graphCheckCode)

		graphCheckCodeEnable, err = process(graphCheckCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable == 0 {
			return nil
		}

		log.Printf("Captcha verification failed (attempt %d/%d), retrying with new captcha...", attempt, maxAttempts)
	}

	if graphCheckCodeEnable != 0 {
		return fmt.Errorf("captcha verification failed after %d attempts", maxAttempts)
	}
	return nil
}

func (s *Session) GetAuthInfoList() ([]AuthInfo, error) {
	_, list, err := s.authConfig(false, true)
	return list, err
}

func (s *Session) continueAuth(step authStep) error {
	for attempt := 0; attempt < maxAuthSteps; attempt++ {
		log.DebugPrintf("Continue authentication: service=%s smsMode=%d", step.Service, step.SMSMode)

		var err error
		switch step.Service {
		case "":
			return nil
		case "auth/authCheck":
			step, err = s.authCheck()
		case "auth/sms":
			step, err = s.completeSMS(step)
		case "auth/customSms":
			step, err = s.completeCustomSMS()
		default:
			return fmt.Errorf("unsupported next authentication service: %s", step.Service)
		}
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("authentication chain exceeded %d steps", maxAuthSteps)
}

func (s *Session) completeSMS(step authStep) (authStep, error) {
	switch step.SMSMode {
	case smsWithAuthID:
		// HITSZ-style gateways refresh the ticket-bearing auth config before
		// querying the phone number and sending the SMS.
		if _, _, err := s.authConfig(true, true); err != nil {
			return authStep{}, err
		}
	case smsWithoutAuthID:
		// SARI-style gateways refresh auth config after sending the SMS.
	default:
		return authStep{}, fmt.Errorf("unknown SMS authentication mode")
	}

	phoneNumbers, err := s.phoneNumber(step.AuthID)
	if err != nil {
		log.Printf("Warning: failed to get phone number: %v", err)
	} else if len(phoneNumbers) > 0 {
		log.Printf("Phone number: %s", strings.Join(phoneNumbers, ", "))
	}

	if err := s.authSms(step); err != nil {
		return authStep{}, err
	}

	if step.SMSMode == smsWithoutAuthID {
		if _, _, err := s.authConfig(true, true); err != nil {
			return authStep{}, err
		}
	}

	return s.smsCheckCode(step)
}

func (s *Session) Login(method LoginMethod, opts LoginOptions) (LoginResult, error) {
	isHITSZ := false
	switch method.(type) {
	case HITSZSSOLogin, *HITSZSSOLogin:
		isHITSZ = true
		// This is deliberately before authConfig: it covers the initial aTrust
		// request, the CAS callback, and every IdP request made by this Session.
		s.enableTLSVerification()
	}
	// A Session may be reused.  Do not let a former HITSZ browser identity
	// bleed into a later legacy aTrust login.
	s.hitszBrowserMode = isHITSZ

	sid := ""
	if len(opts.Cookies) > 0 {
		for _, cookie := range opts.Cookies {
			s.rememberCookieURL(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme})
			if cookie.Host == s.baseHost && cookie.Scheme == "https" && cookie.Name == "sid" {
				sid = cookie.Value
			}

			c := &http.Cookie{
				Name: cookie.Name, Value: cookie.Value, Path: cookie.Path,
				Domain: cookie.Domain, Expires: cookie.Expires,
				RawExpires: cookie.RawExpires, MaxAge: cookie.MaxAge,
				Secure: cookie.Secure, HttpOnly: cookie.HttpOnly,
				SameSite: cookie.SameSite,
			}
			s.client.Jar.SetCookies(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme}, []*http.Cookie{c})
		}
	}

	s.deviceID = opts.DeviceID
	s.env = base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + opts.DeviceID + `"}`))

	isLogin, authInfoList, err := s.authConfig(false, true)
	if err != nil {
		return LoginResult{}, err
	}
	if isLogin == 1 {
		log.Println("Already logged in")
		username, err := s.onlineInfo()
		return LoginResult{
			Username: username,
			SID:      sid,
			Cookies:  opts.Cookies,
		}, err
	}

	if method == nil {
		return LoginResult{}, fmt.Errorf("login method is nil, but user is not logged in")
	}
	var foundAuthInfo *AuthInfo
	for _, authInfo := range authInfoList {
		if authInfo.AuthType == method.AuthType() && authInfo.LoginDomain == method.LoginDomain() {
			foundAuthInfo = &authInfo
			break
		}
	}
	if foundAuthInfo == nil {
		log.Printf("Available authentication methods: %+v", authInfoList)
		return LoginResult{}, fmt.Errorf("auth type/login domain combination not found: auth type: %s, login domain: %s", method.AuthType(), method.LoginDomain())
	}

	log.Printf("Starting login with auth type: %s, login domain: %s", method.AuthType(), method.LoginDomain())
	err = method.login(s, *foundAuthInfo)
	if err != nil {
		return LoginResult{}, err
	}

	if isHITSZ {
		err = s.hitszPostCAS()
	} else {
		err = s.reportEnv()
	}
	if err != nil {
		return LoginResult{}, err
	}

	err = s.continueAuth(authStep{Service: "auth/authCheck"})
	if err != nil {
		return LoginResult{}, err
	}

	username, err := s.onlineInfo()
	if err != nil {
		return LoginResult{}, err
	}

	cookies := make([]Cookie, 0)
	seenCookies := map[string]bool{}
	for _, cookieURL := range s.cookieURLs {
		for _, cookie := range s.client.Jar.Cookies(cookieURL) {
			if cookieURL.Host == s.baseHost && cookie.Name == "sid" {
				sid = cookie.Value
			}
			key := cookieURL.Scheme + "://" + cookieURL.Host + "/" + cookie.Name + "/" + cookie.Path
			if seenCookies[key] {
				continue
			}
			seenCookies[key] = true
			cookies = append(cookies, Cookie{
				Host: cookieURL.Host, Scheme: cookieURL.Scheme, Name: cookie.Name, Value: cookie.Value,
				Path: cookie.Path, Domain: cookie.Domain, Expires: cookie.Expires,
				RawExpires: cookie.RawExpires, MaxAge: cookie.MaxAge, Secure: cookie.Secure,
				HttpOnly: cookie.HttpOnly, SameSite: cookie.SameSite,
			})
		}
	}

	return LoginResult{
		Username: username,
		SID:      sid,
		Cookies:  cookies,
	}, nil
}

func (s *Session) rememberCookieURL(u *url.URL) {
	if u == nil || u.Host == "" || u.Scheme == "" {
		return
	}
	if s.cookieURLs == nil {
		s.cookieURLs = make(map[string]*url.URL)
	}
	key := u.Scheme + "://" + u.Host
	s.cookieURLs[key] = &url.URL{Scheme: u.Scheme, Host: u.Host}
}

// sameHTTPSHost treats an omitted HTTPS port and :443 as the same authority.
// HITSZ's IdP includes :443 in the CAS service parameter but its final
// redirect often omits it.
func sameHTTPSHost(left, right string) bool {
	leftURL, leftErr := url.Parse("https://" + left)
	rightURL, rightErr := url.Parse("https://" + right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftHost := strings.TrimSuffix(strings.ToLower(leftURL.Hostname()), ".")
	rightHost := strings.TrimSuffix(strings.ToLower(rightURL.Hostname()), ".")
	leftPort, rightPort := leftURL.Port(), rightURL.Port()
	if leftPort == "" {
		leftPort = "443"
	}
	if rightPort == "" {
		rightPort = "443"
	}
	return leftHost == rightHost && leftPort == rightPort
}
