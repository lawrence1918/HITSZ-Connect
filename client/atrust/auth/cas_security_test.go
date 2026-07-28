package auth

import (
	"bytes"
	"errors"
	"io"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	projectlog "github.com/mythologyli/zju-connect/log"
)

type casRoundTripFunc func(*http.Request) (*http.Response, error)

func (f casRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func captureAuthLog(t *testing.T, debug bool) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previousOutput := stdlog.Writer()
	stdlog.SetOutput(&output)
	if debug {
		projectlog.EnableDebug()
	} else {
		projectlog.DisableDebug()
	}
	t.Cleanup(func() {
		projectlog.DisableDebug()
		stdlog.SetOutput(previousOutput)
	})
	return &output
}

func captureAuthDebugLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	return captureAuthLog(t, true)
}

func TestOnlineInfoDoesNotLogUsername(t *testing.T) {
	const syntheticUsername = "synthetic-student-that-must-not-be-logged"
	const responseBody = `{"code":7,"data":{"username":"` + syntheticUsername + `"}}`

	for _, test := range []struct {
		name  string
		debug bool
	}{
		{name: "ordinary", debug: false},
		{name: "debug", debug: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := captureAuthLog(t, test.debug)
			session := &Session{
				baseURL: "https://trust.synthetic.example",
				client: &http.Client{Transport: casRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(responseBody)),
						Request:    request,
					}, nil
				})},
			}

			if _, err := session.onlineInfo(); err == nil {
				t.Fatal("onlineInfo unexpectedly succeeded for a non-zero response code")
			}
			logged := output.String()
			for _, sensitive := range []string{syntheticUsername, responseBody, `"username"`} {
				if strings.Contains(logged, sensitive) {
					t.Fatalf("onlineInfo log exposed the synthetic username/body (debug=%t): %q", test.debug, logged)
				}
			}
			if !strings.Contains(logged, "onlineInfo failed with code 7") {
				t.Fatalf("onlineInfo log lost safe failure context (debug=%t): %q", test.debug, logged)
			}
		})
	}
}

func TestParsePortalTicketFromRedirectRedactsDebugLog(t *testing.T) {
	const syntheticTicket = "ST-synthetic-ticket-that-must-not-be-logged"
	portalData := url.QueryEscape(`{"ticket":"` + syntheticTicket + `"}`)
	redirect := "https://trust.synthetic.example/portal/shortcut.html?data=" + portalData
	output := captureAuthDebugLog(t)

	ticket, err := parsePortalTicketFromRedirect(redirect, "trust.synthetic.example")
	if err != nil {
		t.Fatal(err)
	}
	if ticket != syntheticTicket {
		t.Fatal("portal redirect did not return the synthetic ticket")
	}

	logged := output.String()
	for _, sensitive := range []string{syntheticTicket, "?data=", portalData} {
		if strings.Contains(logged, sensitive) {
			t.Fatalf("portal redirect debug log exposed sensitive query data: %q", logged)
		}
	}
	if !strings.Contains(logged, "https://trust.synthetic.example/portal/shortcut.html (query redacted)") {
		t.Fatalf("portal redirect debug log lost its safe request context: %q", logged)
	}
}

func TestCASCallbackResponseDoesNotLogTickets(t *testing.T) {
	const callbackTicket = "ST-synthetic-callback-query-ticket"
	const portalTicket = "ST-synthetic-portal-response-ticket"
	portalData := url.QueryEscape(`{"ticket":"` + portalTicket + `"}`)
	portalRedirect := "https://trust.synthetic.example/portal/shortcut.html?data=" + portalData
	responseBody := `<a href="` + portalRedirect + `">synthetic redirect containing ` + portalTicket + `</a>`
	output := captureAuthDebugLog(t)

	session := &Session{
		baseHost: "trust.synthetic.example",
		client: &http.Client{Transport: casRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Status:     "302 Found",
				Header:     http.Header{"Location": []string{portalRedirect}},
				Body:       io.NopCloser(strings.NewReader(responseBody)),
				Request:    request,
			}, nil
		})},
	}
	callback := "https://trust.synthetic.example/passport/v1/auth/cas?sfDomain=synthetic&ticket=" + callbackTicket
	if err := session.cas(callback); err != nil {
		t.Fatal(err)
	}
	if session.ticket != portalTicket {
		t.Fatal("CAS callback did not retain the synthetic portal ticket")
	}

	logged := output.String()
	for _, sensitive := range []string{callbackTicket, portalTicket, "?data=", portalData, responseBody} {
		if strings.Contains(logged, sensitive) {
			t.Fatalf("CAS callback debug log exposed ticket-bearing data: %q", logged)
		}
	}
	if !strings.Contains(logged, "Received CAS callback response:") {
		t.Fatalf("CAS callback debug log lost its safe response metadata: %q", logged)
	}
}

func TestCASCallbackTransportErrorRedactsTicket(t *testing.T) {
	const syntheticTicket = "ST-synthetic-callback-ticket"
	callback := "https://trust.synthetic.example/passport/v1/auth/cas?sfDomain=synthetic&ticket=" + syntheticTicket

	session := &Session{client: &http.Client{Transport: casRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.URL.Query().Get("ticket"); got != syntheticTicket {
			t.Errorf("callback request did not contain the synthetic test ticket")
		}
		return nil, errors.New("synthetic transport failure")
	})}}

	err := session.cas(callback)
	if err == nil {
		t.Fatal("CAS callback unexpectedly succeeded")
	}
	if got := err.Error(); got != "CAS callback request failed" {
		t.Fatalf("CAS callback error was not sanitized: %q", got)
	}
	for _, sensitive := range []string{syntheticTicket, callback, "sfDomain=", "ticket="} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("CAS callback error exposed sensitive URL data: %q", err)
		}
	}
}
