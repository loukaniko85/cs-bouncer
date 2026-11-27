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

func TestPrepareMembers(t *testing.T) {
	got := prepareMembers([]string{
		"1.2.3.4", "1.2.3.4/32", "2001:db8::/64", "5.6.7.0/24", "1.2.3.4",
	}, 10000)
	require.Equal(t, []string{"1.2.3.4", "5.6.7.0/24"}, got)

	got = prepareMembers([]string{"1.2.3.4", "5.6.7.0/24", "9.9.9.9"}, 1)
	require.Equal(t, []string{"1.2.3.4"}, got)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "abc"})
	w.Header().Set("X-CSRF-Token", "csrf123")
	_, _ = w.Write([]byte(`{}`))
}

func TestSyncGroupCreatesAndUpdates(t *testing.T) {
	created, updated := false, false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			loginHandler(w, r)
			return
		}
		if r.Method == http.MethodGet {
			data := "[]"
			if created {
				data = `[{"_id":"g1","name":"CrowdSec_Block","group_type":"address-group","group_members":["1.1.1.1"],"site_id":"siteid"}]`
			}
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":` + data + `}`))
			return
		}
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "address-group", payload["group_type"])
		if r.Method == http.MethodPost {
			created = true
			require.Equal(t, "/api/s/default/rest/firewallgroup", r.URL.Path)
		} else {
			updated = true
			require.Equal(t, "/api/s/default/rest/firewallgroup/g1", r.URL.Path)
			require.Equal(t, "g1", payload["_id"])
			require.Equal(t, "siteid", payload["site_id"])
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{}]}`))
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	require.NoError(t, c.SyncGroup(context.Background(), []string{"1.1.1.1"}))
	require.True(t, created)
	require.False(t, updated)
	require.NoError(t, c.SyncGroup(context.Background(), []string{"2.2.2.2"}))
	require.True(t, updated)
}

func TestSyncGroupEmptyMembers(t *testing.T) {
	putCalled := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			loginHandler(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"g1","name":"CrowdSec_Block","site_id":"siteid"}]}`))
			return
		}
		putCalled = true
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		members, ok := payload["group_members"].([]any)
		require.True(t, ok)
		require.Empty(t, members)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	require.Error(t, c.SyncGroup(context.Background(), nil))
	require.True(t, putCalled)
}

func TestSyncGroupRejectsNonOkMeta(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			loginHandler(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"error"},"data":[]}`))
	}))
	defer server.Close()

	c := New(testConfig(server.URL))
	require.ErrorContains(t, c.SyncGroup(context.Background(), []string{"1.1.1.1"}), "rc")
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
