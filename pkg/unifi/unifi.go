// Package unifi pushes the ranked blocklist into a UniFi Dream Machine Pro
// address group using the local Network controller API.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/httplimit"
)

var SyncTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "unifi_group_sync_total",
	Help: "Successful UniFi address group syncs",
})

var SyncFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "unifi_group_sync_failures_total",
	Help: "Failed UniFi address group syncs",
})

var GroupMembers = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "unifi_group_members",
	Help: "Number of members in the last synced UniFi address group",
})

type groupResponse struct {
	Meta struct {
		RC string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		ID      string   `json:"_id"`
		Name    string   `json:"name"`
		SiteID  string   `json:"site_id"`
		Members []string `json:"group_members"`
	} `json:"data"`
}

// prepareMembers keeps only valid IPv4 members, strips /32, dedupes and caps.
func prepareMembers(ips []string, maxItems int) []string {
	members := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, value := range ips {
		var candidate string
		if host, network, err := net.ParseCIDR(value); err == nil {
			if host.To4() == nil {
				continue
			}
			ones, bits := network.Mask.Size()
			if ones == 32 && bits == 32 {
				candidate = host.String()
			} else {
				candidate = network.String()
			}
		} else {
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() == nil {
				continue
			}
			candidate = parsed.String()
		}
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		members = append(members, candidate)
		if len(members) >= maxItems {
			break
		}
	}
	return members
}

// SyncGroup creates or replaces the configured address group with the members.
func (c *Client) SyncGroup(ctx context.Context, ips []string) error {
	members := prepareMembers(ips, c.config.MaxItems)
	path := "/api/s/" + c.config.Site + "/rest/firewallgroup"
	var current groupResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &current); err != nil {
		SyncFailures.Inc()
		return err
	}
	if current.Meta.RC != "ok" {
		SyncFailures.Inc()
		return fmt.Errorf("unifi list groups returned rc=%q", current.Meta.RC)
	}

	payload := map[string]any{
		"name":          c.config.GroupName,
		"group_type":    "address-group",
		"group_members": members,
		"site_id":       c.config.Site,
	}
	method := http.MethodPost
	target := path
	for _, group := range current.Data {
		if group.Name == c.config.GroupName {
			method = http.MethodPut
			target = path + "/" + group.ID
			payload["_id"] = group.ID
			if group.SiteID != "" {
				payload["site_id"] = group.SiteID
			}
			break
		}
	}

	var result groupResponse
	if err := c.do(ctx, method, target, payload, &result); err != nil {
		SyncFailures.Inc()
		return err
	}
	if result.Meta.RC != "ok" {
		SyncFailures.Inc()
		return fmt.Errorf("unifi group write returned rc=%q", result.Meta.RC)
	}
	SyncTotal.Inc()
	GroupMembers.Set(float64(len(members)))
	return nil
}

// Client is an authenticated UniFi Network controller client.
type Client struct {
	config cfg.UnifiConfig
	http   *http.Client
	token  string
	csrf   string
}

// New builds a client from the UniFi config.
func New(config cfg.UnifiConfig) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
	}
	return &Client{
		config: config,
		http: &http.Client{Timeout: 30 * time.Second, Transport: &httplimit.RoundTripper{
			Next:  transport,
			Rate:  httplimit.DefaultRate,
			Burst: httplimit.DefaultBurst,
		}},
	}
}

func (c *Client) login(ctx context.Context) error {
	credentials, err := json.Marshal(map[string]string{
		"username": c.config.Username,
		"password": c.config.Password,
	})
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.config.URL, "/") + "/api/auth/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(credentials))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("unifi login: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unifi login failed with HTTP %d", resp.StatusCode)
	}
	token := ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "TOKEN" {
			token = cookie.Value
		}
	}
	csrf := resp.Header.Get("X-CSRF-Token")
	if token == "" || csrf == "" {
		return fmt.Errorf("unifi login response is missing TOKEN or X-CSRF-Token")
	}
	c.token, c.csrf = token, csrf
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	url := strings.TrimRight(c.config.URL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "TOKEN="+c.token)
	req.Header.Set("X-CSRF-Token", c.csrf)
	return c.http.Do(req)
}

// do performs an authenticated controller request, re-logging in once on 401.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	if c.token == "" || c.csrf == "" {
		if err := c.login(ctx); err != nil {
			return err
		}
	}
	resp, err := c.request(ctx, method, path, body)
	if err != nil {
		return fmt.Errorf("unifi request %s %s: %w", method, path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.login(ctx); err != nil {
			return err
		}
		resp, err = c.request(ctx, method, path, body)
		if err != nil {
			return fmt.Errorf("unifi request %s %s: %w", method, path, err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("unifi request %s %s failed with HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("unifi response %s %s: %w", method, path, err)
	}
	return nil
}
