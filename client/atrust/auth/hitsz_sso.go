package auth

// HITSZ unified authentication is a CAS provider in front of aTrust.  It is
// deliberately implemented here (rather than in main) so that the same HTTP
// jar keeps the IdP and aTrust cookies throughout the complete redirect flow.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	hitszMFASMS = "sms"
	hitszMFAApp = "app"
	hitszMFAOTP = "otp"
	// HITSZ's browser-fingerprint endpoints are part of the browser SSO flow.
	// Keep one stable browser-like UA across every IdP navigation and AJAX call.
	hitszSSOUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0"
)

// HITSZ's aTrust tenant redirects CAS authentication to this IdP.  Keep the
// list intentionally small: accepting an arbitrary HTTPS host here would
// allow a malicious aTrust redirect to receive the user's university password.
var hitszIDPHostAllowlist = map[string]struct{}{
	"ids-hit-edu-cn-s.hitsz.edu.cn": {},
}

// ErrHITSZCaptchaRequired is returned in non-interactive mode when the IdP
// requires its slider verification before accepting a credential POST.
var ErrHITSZCaptchaRequired = errors.New("HITSZ unified authentication requires interactive slider verification; retry without non-interactive mode")

type HITSZSSOLogin struct {
	Username         string
	Password         string
	Domain           string
	MFAMethod        string
	MFACode          string
	MFAOTPSecret     string
	MFAOTPSecretFile string
	NonInteractive   bool
	RememberSSO      bool
	RememberMFA      bool
}

func (m HITSZSSOLogin) AuthType() string    { return "auth/cas" }
func (m HITSZSSOLogin) LoginDomain() string { return m.Domain }

func (m HITSZSSOLogin) login(s *Session, info AuthInfo) error {
	return s.loginHITSZSSO(info.LoginURL, m)
}

func (s *Session) loginHITSZSSO(loginURL string, opts HITSZSSOLogin) error {
	// Login normally enables this before its first authConfig request. Keep the
	// invariant here too for package callers that invoke the HITSZ method
	// directly: the CAS callback must use the browser-shaped aTrust identity.
	s.hitszBrowserMode = true
	start, err := url.Parse(loginURL)
	if err != nil {
		return errors.New("parse HITSZ CAS URL")
	}
	if !start.IsAbs() {
		base, _ := url.Parse(s.baseURL + "/")
		start = base.ResolveReference(start)
	}
	resp, err := s.doNoRedirect(http.MethodGet, start.String(), nil, nil)
	if err != nil {
		return fmt.Errorf("open HITSZ CAS login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return fmt.Errorf("unexpected HITSZ CAS redirect status: %s", resp.Status)
	}
	idpLogin, err := resp.Location()
	if err != nil {
		return errors.New("HITSZ CAS redirect has no valid location")
	}
	service := idpLogin.Query().Get("service")
	if service == "" {
		return errors.New("HITSZ CAS redirect has no service parameter")
	}
	if err := validateHITSZIDPRedirect(idpLogin, service, s.baseHost, opts.Domain); err != nil {
		return fmt.Errorf("validate HITSZ CAS redirect: %w", err)
	}
	s.rememberCookieURL(idpLogin)

	callback, reused, err := s.hitszExistingSession(idpLogin.String(), service)
	if err != nil {
		return err
	}
	if !reused {
		callback, err = s.hitszCredentialLogin(idpLogin.String(), idpLogin.Scheme+"://"+idpLogin.Host, service, opts)
		if err != nil {
			return err
		}
	}
	if err := s.cas(callback); err != nil {
		return fmt.Errorf("complete HITSZ aTrust CAS callback: %w", err)
	}
	return nil
}

func (s *Session) hitszExistingSession(loginURL, service string) (string, bool, error) {
	resp, err := s.doNoRedirect(http.MethodGet, loginURL, nil, nil)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return "", false, nil
	}
	loc, err := resp.Location()
	if err != nil {
		return "", false, errors.New("HITSZ existing-session redirect has no valid location")
	}
	if isHITSZServiceCallback(loc.String(), service) {
		return loc.String(), true, nil
	}
	return "", false, nil
}

func (s *Session) hitszCredentialLogin(loginURL, origin, service string, opts HITSZSSOLogin) (string, error) {
	resp, err := s.doNoRedirect(http.MethodGet, loginURL, nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HITSZ login page status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	form, salt, err := parseHITSZLoginForm(body)
	if err != nil {
		return "", err
	}
	// HITSZ's IdP establishes MULTIFACTOR_BROWSER_FINGERPRINT before the
	// credential form is submitted. Without that state, a reAuth response can
	// say success yet the final CAS login returns to the MFA view.
	if err := s.hitszBrowserFingerprint(origin, loginURL); err != nil {
		return "", err
	}
	// captchaSwitch=2 on the HITSZ login page means an explicit isNeed=true
	// requires the official slider to be verified in this same cookie session.
	// A normal browser may skip the login page because it has unrelated CAS
	// cookies, so opening ids.hit.edu.cn directly cannot clear this session.
	if required, checkErr := s.hitszCaptchaRequired(origin, loginURL, opts.Username); checkErr == nil && required {
		if opts.NonInteractive {
			return "", ErrHITSZCaptchaRequired
		}
		solver := s.hitszSliderCaptchaSolver
		if solver == nil {
			solver = s.hitszSolveSliderCaptcha
		}
		if err := solver(origin, loginURL); err != nil {
			return "", fmt.Errorf("complete HITSZ slider verification: %w", err)
		}
	}
	password, err := encryptHITSZPassword(opts.Password, salt)
	if err != nil {
		return "", err
	}
	form.Set("username", opts.Username)
	form.Set("password", password)
	form.Set("captcha", "")
	form.Set("rememberMe", strconv.FormatBool(opts.RememberSSO))

	req, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("build HITSZ credential request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", loginURL)
	postResp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return "", err
	}
	defer postResp.Body.Close()
	if postResp.StatusCode == http.StatusFound || postResp.StatusCode == http.StatusSeeOther {
		loc, err := postResp.Location()
		if err != nil {
			return "", errors.New("HITSZ credential redirect has no valid location")
		}
		if isHITSZServiceCallback(loc.String(), service) {
			return loc.String(), nil
		}
		if isHITSZMFAURL(loc.String()) {
			return s.hitszCompleteMFA(origin, service, opts, loc.String(), nil)
		}
		return "", unexpectedHITSZLoginRedirect(loc)
	}
	page, _ := io.ReadAll(postResp.Body)
	if postResp.StatusCode == http.StatusUnauthorized {
		return "", errors.New("HITSZ login was rejected with HTTP 401 (credentials invalid, browser CAPTCHA verification required, or account risk control active)")
	}
	if isHITSZMFAURL(postResp.Request.URL.String()) || isHITSZMFAPage(page) {
		return s.hitszCompleteMFA(origin, service, opts, postResp.Request.URL.String(), page)
	}
	return "", fmt.Errorf("HITSZ login failed with status %s (captcha or credentials may be invalid)", postResp.Status)
}

func (s *Session) hitszCompleteMFA(origin, service string, opts HITSZSSOLogin, pageURL string, page []byte) (string, error) {
	if len(page) == 0 {
		resp, err := s.doNoRedirect(http.MethodGet, pageURL, nil, nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		page, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
	}
	methods := parseHITSZMFAMethods(page)
	method, err := chooseHITSZMFAMethod(methods, opts.MFAMethod, opts.NonInteractive)
	if err != nil {
		return "", err
	}
	// The browser calls systemTime before changing the reAuth type. Besides
	// providing a clock for OTP, this refreshes the IdP's route affinity cookie.
	mfaTime, err := s.hitszMFAServerTime(origin, service)
	if err != nil {
		return "", err
	}
	mfaTimeObservedAt := time.Now()
	if err := s.hitszMFAForm(origin, service, "/authserver/reAuthCheck/changeReAuthType.do", url.Values{
		"isMultifactor": {"true"}, "reAuthType": {method.reauthType}, "service": {service},
	}, true); err != nil {
		return "", err
	}
	if method.name != hitszMFAOTP {
		if _, err := s.hitszMFAFormResponse(origin, service, "/authserver/dynamicCode/getDynamicCodeByReauth.do", url.Values{
			"userName": {opts.Username}, "authCodeTypeName": {method.codeType},
		}, true); err != nil {
			return "", err
		}
	}
	code := strings.TrimSpace(opts.MFACode)
	if method.name == hitszMFAOTP && code == "" {
		secret, secretErr := resolveHITSZOTPSecret(opts)
		if secretErr != nil {
			return "", secretErr
		}
		// systemTime has second precision, while switching the MFA tab takes a
		// little time. Advance it by local elapsed time to avoid using the prior
		// 30-second window right at a boundary.
		code, err = generateHITSZTOTP(secret, mfaTime.Add(time.Since(mfaTimeObservedAt)))
		if err != nil {
			return "", fmt.Errorf("generate HITSZ OTP code: %w", err)
		}
	}
	if code == "" && method.name != hitszMFAOTP {
		if provider := currentHITSZMFACodeProvider(); provider != nil {
			code, err = provider(method.name)
			if err != nil {
				return "", fmt.Errorf("read HITSZ %s MFA code: %w", method.name, err)
			}
			code = strings.TrimSpace(code)
		}
	}
	if code == "" {
		if opts.NonInteractive {
			return "", errors.New("HITSZ MFA code required in non-interactive mode")
		}
		fmt.Printf("HITSZ %s verification code: ", method.name)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read HITSZ MFA code: %w", err)
		}
		code = strings.TrimSpace(line)
	}
	if code == "" {
		return "", errors.New("empty HITSZ MFA code")
	}
	values := url.Values{"service": {service}, "reAuthType": {method.reauthType}, "isMultifactor": {"true"}, "password": {""}, "dynamicCode": {""}, "uuid": {""}, "answer1": {""}, "answer2": {""}, "otpCode": {""}, "skipTmpReAuth": {strconv.FormatBool(opts.RememberMFA)}}
	if method.name == hitszMFAOTP {
		values.Set("otpCode", code)
	} else {
		values.Set("dynamicCode", code)
	}
	callback, body, err := s.hitszMFASubmit(origin, service, values)
	if err != nil {
		return "", err
	}
	if callback != "" {
		return callback, nil
	}
	if !bytes.Contains(bytes.ToLower(body), []byte("reauth_success")) && !bytes.Contains(body, []byte("认证成功")) {
		return "", errors.New("HITSZ MFA verification failed")
	}

	login := origin + "/authserver/login?" + url.Values{"service": {service}}.Encode()
	req, err := http.NewRequest(http.MethodGet, login, nil)
	if err != nil {
		return "", errors.New("build HITSZ post-MFA callback request")
	}
	req.Header.Set("Referer", pageURL)
	req.Header.Set("User-Agent", hitszSSOUserAgent)
	// HITSZ may redirect through an internal reAuth page before issuing the
	// CAS callback. Stop only at the requested aTrust service, not at the
	// first redirect as doNoRedirect does.
	resp, err := s.doUntilHITSZService(req, service)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		trace := strings.Join(s.hitszRedirectTrace, " -> ")
		if trace == "" {
			trace = "no redirects observed"
		}
		return "", fmt.Errorf("HITSZ MFA completed but service callback was not returned (final: %s %s; redirects: %s)", resp.Status, redactedHITSZURL(resp.Request.URL), trace)
	}
	loc, err := resp.Location()
	if err != nil {
		return "", errors.New("HITSZ MFA callback has no valid location")
	}
	if !isHITSZServiceCallback(loc.String(), service) {
		// CAS tickets are carried in the Location query.  Do not expose them in
		// an error that is normally copied into terminal logs or support chats.
		return "", errors.New("unexpected HITSZ MFA callback")
	}
	return loc.String(), nil
}

type hitszMFAMethod struct{ name, reauthType, codeType string }

func validateHITSZIDPRedirect(idpLogin *url.URL, service, baseHost, domain string) error {
	host, ok := normalizedHITSZHTTPSHost(idpLogin)
	if !ok {
		return errors.New("HITSZ IdP URL must use HTTPS with a normal verified authority")
	}
	if _, ok := hitszIDPHostAllowlist[host]; !ok {
		return errors.New("HITSZ IdP URL host is not allowed")
	}
	return validateHITSZCASService(service, baseHost, domain)
}

// normalizedHITSZHTTPSHost accepts only a conventional HTTPS authority.  An
// omitted port and :443 are equivalent; other ports, userinfo, and malformed
// authorities are rejected before credentials can be posted to the IdP.
func normalizedHITSZHTTPSHost(u *url.URL) (string, bool) {
	if u == nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", false
	}
	rawHost := strings.TrimSuffix(strings.ToLower(u.Host), ".")
	if rawHost != host && rawHost != host+":443" {
		return "", false
	}
	return host, true
}

func validateHITSZCASService(service, baseHost, domain string) error {
	target, err := url.Parse(service)
	if err != nil {
		return errors.New("parse HITSZ CAS service")
	}
	if !strings.EqualFold(target.Scheme, "https") || target.User != nil || !sameHTTPSHost(target.Host, baseHost) {
		return errors.New("HITSZ CAS service does not target this aTrust HTTPS host")
	}
	if target.Path != "/passport/v1/auth/cas" || target.Fragment != "" {
		return errors.New("HITSZ CAS service has an invalid callback path")
	}
	sfDomains := target.Query()["sfDomain"]
	if len(sfDomains) != 1 || sfDomains[0] != domain {
		return errors.New("HITSZ CAS service sfDomain does not match the selected login domain")
	}
	return nil
}

func parseHITSZMFAMethods(page []byte) []hitszMFAMethod {
	root, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []hitszMFAMethod
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			id, typ, class := htmlAttr(n, "id"), htmlAttr(n, "data-type"), htmlAttr(n, "class")
			if typ == "" && strings.HasPrefix(id, "tab_") {
				typ = strings.TrimPrefix(id, "tab_")
			}
			if typ == "" && (hasHITSZClass(class, "changeReAuthTypes") || (id == "10" && hasHITSZClass(class, "reauth-tab-more-item"))) {
				typ = id
			}
			if !seen[typ] {
				switch typ {
				case "13":
					out = append(out, hitszMFAMethod{hitszMFAApp, "13", "reAuthWeLinkDynamicCodeType"})
					seen[typ] = true
				case "3":
					out = append(out, hitszMFAMethod{hitszMFASMS, "3", "reAuthDynamicCodeType"})
					seen[typ] = true
				case "10":
					out = append(out, hitszMFAMethod{hitszMFAOTP, "10", ""})
					seen[typ] = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

func hasHITSZClass(class, wanted string) bool {
	for _, token := range strings.Fields(class) {
		if strings.EqualFold(token, wanted) {
			return true
		}
	}
	return false
}

func chooseHITSZMFAMethod(methods []hitszMFAMethod, requested string, nonInteractive bool) (hitszMFAMethod, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested != "" {
		for _, method := range methods {
			if method.name == requested {
				return method, nil
			}
		}
		return hitszMFAMethod{}, fmt.Errorf("requested HITSZ MFA method %q is unavailable", requested)
	}
	for _, method := range methods {
		if method.name == hitszMFAApp {
			return method, nil
		}
	}
	for _, method := range methods {
		if method.name == hitszMFASMS {
			return method, nil
		}
	}
	for _, method := range methods {
		if method.name == hitszMFAOTP {
			return method, nil
		}
	}
	if nonInteractive {
		return hitszMFAMethod{}, errors.New("HITSZ MFA method required in non-interactive mode")
	}
	return hitszMFAMethod{}, errors.New("HITSZ MFA required but no supported method is available")
}

func (s *Session) hitszMFAForm(origin, service, path string, values url.Values, ajax bool) error {
	_, err := s.hitszMFAFormResponse(origin, service, path, values, ajax)
	return err
}

func (s *Session) hitszMFAFormResponse(origin, service, path string, values url.Values, ajax bool) ([]byte, error) {
	u, _ := url.Parse(origin + path)
	if ajax {
		q := u.Query()
		q.Set("sf_request_type", "ajax")
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, errors.New("build HITSZ MFA request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service="+url.QueryEscape(service))
	if ajax {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HITSZ MFA request failed: %s", resp.Status)
	}
	var result map[string]any
	if json.Unmarshal(body, &result) == nil {
		if code, ok := result["errCode"].(string); ok && code == "206302" {
			return nil, errors.New("HITSZ MFA session expired")
		}
	}
	return body, nil
}

// hitszMFASubmit mirrors the HITSZ browser's AJAX reAuthSubmit request. The
// IdP uses this request's cookie state to establish the post-MFA SSO session.
func (s *Session) hitszMFASubmit(origin, service string, values url.Values) (string, []byte, error) {
	u, _ := url.Parse(origin + "/authserver/reAuthCheck/reAuthSubmit.do")
	q := u.Query()
	q.Set("sf_request_type", "ajax")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return "", nil, errors.New("build HITSZ MFA submit request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service="+url.QueryEscape(service))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", nil, readErr
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", nil, fmt.Errorf("HITSZ MFA submit failed: %s", resp.Status)
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		location, locationErr := resp.Location()
		if locationErr != nil {
			return "", nil, errors.New("HITSZ MFA submit redirect has no location")
		}
		if isHITSZServiceCallback(location.String(), service) {
			return location.String(), body, nil
		}
		return "", nil, fmt.Errorf("unexpected HITSZ MFA submit redirect: %s", redactedHITSZURL(location))
	}
	return "", body, nil
}

func (s *Session) hitszBrowserFingerprint(origin, loginURL string) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("generate HITSZ browser fingerprint: %w", err)
	}
	u, _ := url.Parse(origin + "/authserver/bfp/info")
	q := u.Query()
	q.Set("bfp", strings.ToUpper(hex.EncodeToString(random[:])))
	q.Set("_", strconv.FormatInt(time.Now().UnixMilli(), 10))
	q.Set("sf_request_type", "ajax")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("build HITSZ browser fingerprint request")
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", loginURL)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return fmt.Errorf("request HITSZ browser fingerprint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("HITSZ browser fingerprint request failed: %s", resp.Status)
	}
	// Drain the body so the connection can be reused; all useful state arrives
	// in Set-Cookie and is managed by the session jar.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	originURL, _ := url.Parse(origin)
	if originURL == nil || s.client.Jar == nil {
		return errors.New("HITSZ browser fingerprint cookie jar is unavailable")
	}
	for _, cookie := range s.client.Jar.Cookies(originURL) {
		if cookie.Name == "MULTIFACTOR_BROWSER_FINGERPRINT" {
			return nil
		}
	}
	return errors.New("HITSZ browser fingerprint cookie was not returned")
}

func (s *Session) hitszCaptchaRequired(origin, loginURL, username string) (bool, error) {
	u, err := url.Parse(origin + "/authserver/checkNeedCaptcha.htl")
	if err != nil {
		return false, errors.New("build HITSZ CAPTCHA preflight request")
	}
	q := u.Query()
	q.Set("username", username)
	q.Set("_", strconv.FormatInt(time.Now().UnixMilli(), 10))
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return false, errors.New("build HITSZ CAPTCHA preflight request")
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Referer", loginURL)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		// Do not wrap net/url errors here: their URL contains the username.
		return false, errors.New("HITSZ CAPTCHA preflight request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("HITSZ CAPTCHA preflight failed with status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, errors.New("read HITSZ CAPTCHA preflight response")
	}
	var result struct {
		IsNeed json.RawMessage `json:"isNeed"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.IsNeed) == 0 {
		return false, errors.New("parse HITSZ CAPTCHA preflight response")
	}
	var required bool
	if err := json.Unmarshal(result.IsNeed, &required); err == nil {
		return required, nil
	}
	var text string
	if err := json.Unmarshal(result.IsNeed, &text); err == nil {
		required, err = strconv.ParseBool(strings.TrimSpace(text))
		if err == nil {
			return required, nil
		}
	}
	return false, errors.New("parse HITSZ CAPTCHA preflight response")
}

func (s *Session) hitszMFAServerTime(origin, service string) (time.Time, error) {
	u, _ := url.Parse(origin + "/authserver/systemTime")
	q := u.Query()
	q.Set("sf_request_type", "ajax")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return time.Time{}, errors.New("build HITSZ MFA server-time request")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service="+url.QueryEscape(service))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := s.doNoRedirectRequest(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("request HITSZ MFA server time: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return time.Time{}, fmt.Errorf("HITSZ MFA server-time request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}
	var result struct {
		SystemTime string `json:"systemTime"`
	}
	if err := json.Unmarshal(body, &result); err != nil || strings.TrimSpace(result.SystemTime) == "" {
		// The route cookie side effect succeeded, so a local clock is safer than
		// failing an otherwise valid SMS/App authentication on a format change.
		return time.Now(), nil
	}
	location := time.FixedZone("CST", 8*60*60)
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04:05.000", time.RFC3339, time.RFC3339Nano} {
		if parsed, parseErr := time.ParseInLocation(layout, result.SystemTime, location); parseErr == nil {
			return parsed, nil
		}
	}
	return time.Now(), nil
}

func (s *Session) doNoRedirect(method, rawURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, errors.New("build HITSZ SSO request")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return s.doNoRedirectRequest(req)
}

func (s *Session) doNoRedirectRequest(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", hitszSSOUserAgent)
	}
	previous := s.client.CheckRedirect
	s.client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { s.client.CheckRedirect = previous }()
	resp, err := s.client.Do(req)
	if err != nil {
		// net/http wraps transport errors in url.Error, whose text includes the
		// complete request URL (and therefore may include username or tickets).
		return nil, errors.New("HITSZ SSO request failed")
	}
	return resp, nil
}

func (s *Session) doUntilHITSZService(req *http.Request, service string) (*http.Response, error) {
	previous := s.client.CheckRedirect
	trace := make([]string, 0, 4)
	s.client.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		trace = append(trace, redactedHITSZURL(next.URL))
		if isHITSZServiceCallback(next.URL.String(), service) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() {
		s.client.CheckRedirect = previous
		s.hitszRedirectTrace = trace
	}()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("HITSZ SSO redirect request failed")
	}
	return resp, nil
}

func redactedHITSZURL(u *url.URL) string {
	if u == nil {
		return "<nil>"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

func unexpectedHITSZLoginRedirect(u *url.URL) error {
	return fmt.Errorf("unexpected HITSZ login redirect: %s", redactedHITSZURL(u))
}

func parseHITSZLoginForm(page []byte) (url.Values, string, error) {
	root, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return nil, "", err
	}
	var passwordForm *html.Node
	var findForm func(*html.Node)
	findForm = func(n *html.Node) {
		if passwordForm != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" && htmlAttr(n, "id") == "pwdFromId" {
			passwordForm = n
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			findForm(child)
		}
	}
	findForm(root)
	if passwordForm == nil {
		return nil, "", errors.New("HITSZ login page has no password form")
	}
	values := url.Values{}
	salt := ""
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, value, id, inputType := htmlAttr(n, "name"), htmlAttr(n, "value"), htmlAttr(n, "id"), htmlAttr(n, "type")
			if strings.EqualFold(strings.TrimSpace(inputType), "hidden") && name != "" {
				values.Set(name, value)
			}
			if id == "pwdEncryptSalt" || name == "pwdEncryptSalt" {
				salt = value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(passwordForm)
	if salt == "" {
		return nil, "", errors.New("HITSZ login page has no pwdEncryptSalt")
	}
	return values, salt, nil
}

func htmlAttr(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func encryptHITSZPassword(password, salt string) (string, error) {
	if len(salt) != aes.BlockSize {
		return "", errors.New("HITSZ pwdEncryptSalt must be 16 bytes")
	}
	iv, err := hitszRandomString(aes.BlockSize)
	if err != nil {
		return "", err
	}
	prefix, err := hitszRandomString(64)
	if err != nil {
		return "", err
	}
	plain := pkcs7Pad([]byte(prefix+password), aes.BlockSize)
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, []byte(iv)).CryptBlocks(ciphertext, plain)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func hitszRandomString(length int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		var n [1]byte
		for {
			if _, err := rand.Read(n[:]); err != nil {
				return "", err
			}
			if int(n[0]) < 248 {
				b[i] = alphabet[int(n[0])%len(alphabet)]
				break
			}
		}
	}
	return string(b), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func isHITSZMFAURL(raw string) bool {
	return strings.Contains(strings.ToLower(raw), "reauthloginview.do") || strings.Contains(strings.ToLower(raw), "ismultifactor=true")
}
func isHITSZMFAPage(page []byte) bool {
	lower := bytes.ToLower(page)
	return bytes.Contains(lower, []byte("reauthloginview.do")) ||
		bytes.Contains(lower, []byte("changereauthtypes")) ||
		bytes.Contains(lower, []byte("data-type=\"13\"")) ||
		bytes.Contains(lower, []byte("data-type=\"3\"")) ||
		bytes.Contains(lower, []byte("data-type=\"10\""))
}
func isHITSZServiceCallback(raw, service string) bool {
	callback, callbackErr := url.Parse(raw)
	target, targetErr := url.Parse(service)
	if callbackErr != nil || targetErr != nil || !strings.EqualFold(callback.Scheme, "https") || !strings.EqualFold(target.Scheme, "https") || callback.User != nil || target.User != nil {
		return false
	}
	if !sameHTTPSHost(callback.Host, target.Host) || callback.Path != target.Path {
		return false
	}
	callbackQuery := callback.Query()
	for key, expectedValues := range target.Query() {
		actualValues, ok := callbackQuery[key]
		if !ok || len(actualValues) != len(expectedValues) {
			return false
		}
		for _, expected := range expectedValues {
			found := false
			for _, actual := range actualValues {
				if actual == expected {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return callbackQuery.Get("ticket") != ""
}
