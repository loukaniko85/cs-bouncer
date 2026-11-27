// Package httplimit provides a shared HTTP round tripper that throttles
// requests per host and respects Retry-After responses.
package httplimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	DefaultRate  rate.Limit = 4
	DefaultBurst            = 4
)

// Default is the limiter shared by the Cloudflare and UniFi clients.
var Default = &RoundTripper{Rate: DefaultRate, Burst: DefaultBurst}

type hostState struct {
	limiter    *rate.Limiter
	mu         sync.Mutex
	pauseUntil time.Time
}

// RoundTripper wraps a transport with per-host token buckets and Retry-After pauses.
type RoundTripper struct {
	Next  http.RoundTripper
	Rate  rate.Limit
	Burst int

	mu    sync.Mutex
	hosts map[string]*hostState
}

func (rt *RoundTripper) stateFor(host string) *hostState {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.hosts == nil {
		rt.hosts = make(map[string]*hostState)
	}
	state := rt.hosts[host]
	if state == nil {
		state = &hostState{limiter: rate.NewLimiter(rt.Rate, rt.Burst)}
		rt.hosts[host] = state
	}
	return state
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

func (state *hostState) extendPause(delay time.Duration) {
	if delay <= 0 {
		return
	}
	until := time.Now().Add(delay)
	state.mu.Lock()
	defer state.mu.Unlock()
	if until.After(state.pauseUntil) {
		state.pauseUntil = until
	}
}

func (state *hostState) waitPause(ctx context.Context) error {
	state.mu.Lock()
	pauseUntil := state.pauseUntil
	state.mu.Unlock()
	if pauseUntil.IsZero() || time.Now().After(pauseUntil) {
		return nil
	}
	timer := time.NewTimer(time.Until(pauseUntil))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RoundTrip waits for a host token, performs the request, and records a
// Retry-After pause for subsequent requests. The rejected request is returned
// unchanged and is never replayed.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	state := rt.stateFor(req.URL.Host)
	if err := state.waitPause(req.Context()); err != nil {
		return nil, err
	}
	if err := state.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	// A concurrent 429 may have extended the pause while this request waited
	// for a token; recheck before sending.
	if err := state.waitPause(req.Context()); err != nil {
		return nil, err
	}
	next := rt.Next
	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusTooManyRequests {
		state.extendPause(parseRetryAfter(resp.Header.Get("Retry-After")))
	}
	return resp, err
}
