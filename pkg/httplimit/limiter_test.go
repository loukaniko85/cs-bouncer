package httplimit

import (
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

func TestParseRetryAfter(t *testing.T) {
	require.Equal(t, 3*time.Second, parseRetryAfter("3"))
	require.Equal(t, time.Duration(0), parseRetryAfter("garbage"))
	date := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	require.Greater(t, parseRetryAfter(date), time.Duration(0))
}
