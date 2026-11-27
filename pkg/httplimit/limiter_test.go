package httplimit

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestRoundTripperLimits(t *testing.T) {
	transport := &RoundTripper{
		Next:    roundTripperFunc(func(r *http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200}, nil }),
		Limiter: rate.NewLimiter(4, 4),
	}
	client := &http.Client{Transport: transport}
	start := time.Now()
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRoundTripperRetryAfter(t *testing.T) {
	calls := 0
	transport := &RoundTripper{
		Next: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{
					StatusCode: 429,
					Header:     http.Header{"Retry-After": []string{"1"}},
				}, nil
			}
			return &http.Response{StatusCode: 200}, nil
		}),
		Limiter: rate.NewLimiter(100, 100),
	}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, 429, resp.StatusCode)

	start := time.Now()
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond)
	require.Equal(t, 2, calls, "the rejected request must not be replayed")
}

func TestRetryAfterPauseIsMonotonic(t *testing.T) {
	rt := &RoundTripper{}
	rt.extendPause(2 * time.Second)
	first := rt.pauseUntil
	rt.extendPause(time.Second)
	require.Equal(t, first, rt.pauseUntil, "a shorter Retry-After must not cut an existing pause")

	rt.extendPause(10 * time.Minute)
	require.LessOrEqual(t, rt.pauseUntil.Sub(time.Now()), 5*time.Minute, "pause must be capped")
}

func TestRetryAfterRespectsCancellation(t *testing.T) {
	calls := 0
	transport := &RoundTripper{
		Next: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"2"}}}, nil
		}),
		Limiter: rate.NewLimiter(100, 100),
	}
	client := &http.Client{Transport: transport}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test", nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	require.NoError(t, err)
	cancel()

	start := time.Now()
	_, err = client.Do(req)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestParseRetryAfter(t *testing.T) {
	require.Equal(t, 3*time.Second, parseRetryAfter("3"))
	require.Equal(t, time.Duration(0), parseRetryAfter("garbage"))
	date := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	require.Greater(t, parseRetryAfter(date), time.Duration(0))
}
