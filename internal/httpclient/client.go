// Package httpclient prevents SDK requests from forwarding credentials, proofs
// or sensitive request bodies through an endpoint's HTTP redirect (SDK-008).
package httpclient

import "net/http"

// Do preserves the configured transport, cookies and deadlines, but returns
// redirect responses to the caller. It never mutates the caller's client.
func Do(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return copy.Do(request)
}
