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
		Enabled:            true,
		Mode:               "local",
		URL:                url,
		APIKey:             "test-api-key",
		Site:               "default",
		ListName:           "CrowdSec_Blocklist",
		MaxItems:           10000,
		InsecureSkipVerify: true,
	}
}

func TestPrepareMembers(t *testing.T) {
	got := prepareMembers([]string{
		"1.2.3.4", "1.2.3.4/32", "2001:db8::/64", "5.6.7.0/24", "1.2.3.4",
	}, 10000)
	require.Equal(t, []map[string]string{
		{"type": "IP_ADDRESS", "value": "1.2.3.4"},
		{"type": "SUBNET", "value": "5.6.7.0/24"},
	}, got)

	got = prepareMembers([]string{"1.2.3.4", "5.6.7.0/24", "9.9.9.9"}, 1)
	require.Len(t, got, 1)
}

func TestSyncGroupCreatesAndUpdatesWithAPIKey(t *testing.T) {
	created := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "test-api-key", r.Header.Get("X-API-Key"))
		if r.URL.Path == "/proxy/network/integration/v1/sites" {
			_, _ = w.Write([]byte(`{"data":[{"id":"site-uuid","name":"default","internalReference":"default"}],"totalCount":1}`))
			return
		}
		if r.Method == http.MethodGet {
			data := "[]"
			if created {
				data = `[{"id":"list-uuid","name":"CrowdSec_Blocklist","type":"IPV4_ADDRESSES","items":[{"type":"IP_ADDRESS","value":123}]}]`
			}
			_, _ = w.Write([]byte(`{"data":` + data + `,"totalCount":1}`))
			return
		}
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "IPV4_ADDRESSES", payload["type"])
		if r.Method == http.MethodPost {
			created = true
			require.Equal(t, "/proxy/network/integration/v1/sites/site-uuid/traffic-matching-lists", r.URL.Path)
			w.WriteHeader(http.StatusCreated)
		} else {
			require.Equal(t, "/proxy/network/integration/v1/sites/site-uuid/traffic-matching-lists/list-uuid", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"list-uuid","name":"CrowdSec_Blocklist","type":"IPV4_ADDRESSES"}`))
	}))
	defer server.Close()

	client, err := New(testConfig(server.URL))
	require.NoError(t, err)
	require.NoError(t, client.SyncGroup(context.Background(), []string{"1.1.1.1"}))
	require.True(t, created)
	require.NoError(t, client.SyncGroup(context.Background(), []string{"2.2.2.2"}))
}

func TestSyncGroupEmptyUsesPlaceholder(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy/network/integration/v1/sites" {
			_, _ = w.Write([]byte(`{"data":[{"id":"site-uuid","name":"default","internalReference":"default"}],"totalCount":1}`))
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":[{"id":"list-uuid","name":"CrowdSec_Blocklist","type":"IPV4_ADDRESSES"}],"totalCount":1}`))
			return
		}
		var payload struct {
			Items []map[string]string `json:"items"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, []map[string]string{{"type": "IP_ADDRESS", "value": "192.0.2.1"}}, payload.Items)
		_, _ = w.Write([]byte(`{"id":"list-uuid","name":"CrowdSec_Blocklist","type":"IPV4_ADDRESSES"}`))
	}))
	defer server.Close()

	client, err := New(testConfig(server.URL))
	require.NoError(t, err)
	require.NoError(t, client.SyncGroup(context.Background(), nil))
}

func TestResolveSitePaginates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") == "0" {
			_, _ = w.Write([]byte(`{"data":[{"id":"other","name":"Other","internalReference":"other"}],"totalCount":2}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"site-uuid","name":"default","internalReference":"default"}],"totalCount":2}`))
	}))
	defer server.Close()

	client, err := New(testConfig(server.URL))
	require.NoError(t, err)
	siteID, err := client.resolveSite(context.Background())
	require.NoError(t, err)
	require.Equal(t, "site-uuid", siteID)
}

func TestCloudBaseURL(t *testing.T) {
	config := testConfig("")
	config.Mode = "cloud"
	config.ConsoleID = "console-id"
	client, err := New(config)
	require.NoError(t, err)
	require.Equal(t, "https://api.ui.com/v1/connector/consoles/console-id/proxy/network/integration/v1", client.baseURL())
}

func TestNewRejectsBadCAFile(t *testing.T) {
	config := testConfig("https://example.test")
	config.CAFile = "/does/not/exist"
	_, err := New(config)
	require.Error(t, err)
}
