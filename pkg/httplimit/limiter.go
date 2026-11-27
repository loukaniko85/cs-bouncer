// Package httplimit provides a shared HTTP round tripper that throttles
// requests and respects Retry-After responses.
package httplimit

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Default is the limiter shared by the Cloudflare and UniFi clients.
var Default = &RoundTripper{
	Limiter: rate.NewLimiter(4, 4),
}

// RoundTripper wraps a transport with a token bucket and a Retry-After pause.
type RoundTripper struct {
	Next    http.RoundTripper
	Limiter *rate.Limiter

	mu         sync.Mutex
	pauseUntil time.Time
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay > 0 {
			return delay
		}
	}
	return 0
}

// RoundTrip waits for a token, performs the request, and records a Retry-After
// pause for subsequent requests when the server returns 429. The rejected
// request is returned to the caller unchanged and is never replayed.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	pauseUntil := rt.pauseUntil
	rt.mu.Unlock()
	if !pauseUntil.IsZero() && time.Now().Before(pauseUntil) {
		time.Sleep(time.Until(pauseUntil))
	}
	if rt.Limiter != nil {
		if err := rt.Limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	next := rt.Next
	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusTooManyRequests {
		if delay := parseRetryAfter(resp.Header.Get("Retry-After")); delay > 0 {
			rt.mu.Lock()
			rt.pauseUntil = time.Now().Add(delay)
			rt.mu.Unlock()
		}
	}
	return resp, err
}
