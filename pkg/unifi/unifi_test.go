package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

func testConfig(url string) cfg.UnifiConfig {
	return cfg.UnifiConfig{
		URL:                url,
		Site:               "default",
		Username:           "admin",
		Password:           "secret",
		GroupName:          "CrowdSec_Block",
		MaxItems:           10000,
		InsecureSkipVerify: true,
	}
}

func TestLoginStoresCookieAndCSRF(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/auth/login", r.URL.Path)
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "admin", payload["username"])
		require.Equal(t, "secret", payload["password"])
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "abc"})
		w.Header().Set("X-CSRF-Token", "csrf123")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	require.NoError(t, c.login(context.Background()))
	require.Equal(t, "abc", c.token)
	require.Equal(t, "csrf123", c.csrf)
}

func TestDoReloginOn401(t *testing.T) {
	logins := 0
	getCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			logins++
			http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "abc"})
			w.Header().Set("X-CSRF-Token", "csrf123")
			w.WriteHeader(http.StatusOK)
			return
		}
		getCount++
		require.Equal(t, "TOKEN=abc", r.Header.Get("Cookie"))
		require.Equal(t, "csrf123", r.Header.Get("X-CSRF-Token"))
		if getCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	var out struct {
		Meta struct{ RC string `json:"rc"` } `json:"meta"`
	}
	require.NoError(t, c.do(context.Background(), http.MethodGet, "/api/s/default/rest/firewallgroup", nil, &out))
	require.Equal(t, "ok", out.Meta.RC)
	require.Equal(t, 2, logins)
	require.Equal(t, 2, getCount)
}

func TestDoFailsWhenLoginFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	err := c.do(context.Background(), http.MethodGet, "/api/s/default/rest/firewallgroup", nil, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")
}
