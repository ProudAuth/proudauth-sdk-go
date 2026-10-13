package httpclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// SDK-008: real redirect destinations receive neither credentials nor body data.
func TestRequestsDoNotFollowRedirects(t *testing.T) {
	var destinationHits, callbackHits atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationHits.Add(1) }))
	defer destination.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, status) }))
		client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { callbackHits.Add(1); return nil }}
		req, _ := http.NewRequest("POST", origin.URL, strings.NewReader("refresh_token=synthetic-test-secret"))
		req.Header.Set("Authorization", "Bearer synthetic-test-token")
		res, err := Do(client, req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		origin.Close()
		if res.StatusCode != status {
			t.Fatalf("redirect %d became %d", status, res.StatusCode)
		}
		if client.CheckRedirect == nil || client.Timeout != time.Second {
			t.Fatal("caller client was mutated")
		}
	}
	if destinationHits.Load() != 0 || callbackHits.Load() != 0 {
		t.Fatalf("redirect followed: destination %d, callback %d", destinationHits.Load(), callbackHits.Load())
	}
}
