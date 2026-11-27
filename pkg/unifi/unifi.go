// Package unifi pushes the ranked blocklist into a UniFi Traffic Matching List
// using the official API-key Network API.
package unifi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/httplimit"
)

var SyncTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "unifi_group_sync_total",
	Help: "Successful UniFi traffic matching list syncs",
})

var SyncFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "unifi_group_sync_failures_total",
	Help: "Failed UniFi traffic matching list syncs",
})

var GroupMembers = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "unifi_group_members",
	Help: "Number of effective members in the last synced UniFi list",
})

// Client is an authenticated UniFi Network API client.
type Client struct {
	config cfg.UnifiConfig
	http   *http.Client
	siteID string
}

// New builds a client from the UniFi config.
func New(config cfg.UnifiConfig) (*Client, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}
	if config.CAFile != "" {
		pem, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("unifi ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("unifi ca_file contains no valid certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &Client{
		config: config,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &httplimit.RoundTripper{
				Next:  transport,
				Rate:  httplimit.DefaultRate,
				Burst: httplimit.DefaultBurst,
			},
		},
	}, nil
}

func (c *Client) baseURL() string {
	if c.config.Mode == "cloud" {
		return "https://api.ui.com/v1/connector/consoles/" + c.config.ConsoleID + "/proxy/network/integration/v1"
	}
	return strings.TrimRight(c.config.URL, "/") + "/proxy/network/integration/v1"
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.config.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("unifi request %s %s: %w", method, path, err)
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

type page[T any] struct {
	Data       []T `json:"data"`
	TotalCount int `json:"totalCount"`
}

func fetchAll[T any](ctx context.Context, client *Client, path string) ([]T, error) {
	var result []T
	offset := 0
	for {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		var current page[T]
		if err := client.do(ctx, http.MethodGet, fmt.Sprintf("%s%soffset=%d&limit=100", path, separator, offset), nil, &current); err != nil {
			return nil, err
		}
		result = append(result, current.Data...)
		if len(current.Data) == 0 || offset+len(current.Data) >= current.TotalCount {
			return result, nil
		}
		offset += len(current.Data)
	}
}

type site struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

func (c *Client) resolveSite(ctx context.Context) (string, error) {
	if c.siteID != "" {
		return c.siteID, nil
	}
	sites, err := fetchAll[site](ctx, c, "/sites")
	if err != nil {
		return "", err
	}
	for _, candidate := range sites {
		if candidate.Name == c.config.Site {
			c.siteID = candidate.ID
			return c.siteID, nil
		}
	}
	for _, candidate := range sites {
		if candidate.InternalReference == c.config.Site || candidate.ID == c.config.Site {
			c.siteID = candidate.ID
			return c.siteID, nil
		}
	}
	return "", fmt.Errorf("unifi site %q not found", c.config.Site)
}

type trafficMatchingList struct {
	ID    string              `json:"id"`
	Name  string              `json:"name"`
	Type  string              `json:"type"`
	Items []json.RawMessage `json:"items"`
}

// prepareMembers keeps valid IPv4 addresses/subnets, dedupes and caps.
func prepareMembers(ips []string, maxItems int) []map[string]string {
	members := make([]map[string]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, value := range ips {
		var candidate map[string]string
		if strings.Contains(value, "/") {
			host, network, err := net.ParseCIDR(value)
			if err != nil || host.To4() == nil {
				continue
			}
			ones, bits := network.Mask.Size()
			if ones == 32 && bits == 32 {
				candidate = map[string]string{"type": "IP_ADDRESS", "value": host.String()}
			} else {
				candidate = map[string]string{"type": "SUBNET", "value": network.String()}
			}
		} else {
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() == nil {
				continue
			}
			candidate = map[string]string{"type": "IP_ADDRESS", "value": parsed.String()}
		}
		key := candidate["type"] + ":" + candidate["value"]
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		members = append(members, candidate)
		if len(members) >= maxItems {
			break
		}
	}
	return members
}

// SyncGroup creates or replaces the configured IPv4 Traffic Matching List.
func (c *Client) SyncGroup(ctx context.Context, ips []string) error {
	members := prepareMembers(ips, c.config.MaxItems)
	effectiveCount := len(members)
	if len(members) == 0 {
		log.Warn("UniFi blocklist is empty; using documentation-only placeholder 192.0.2.1")
		members = []map[string]string{{"type": "IP_ADDRESS", "value": "192.0.2.1"}}
	}
	siteID, err := c.resolveSite(ctx)
	if err != nil {
		SyncFailures.Inc()
		return err
	}
	path := "/sites/" + siteID + "/traffic-matching-lists"
	lists, err := fetchAll[trafficMatchingList](ctx, c, path)
	if err != nil {
		SyncFailures.Inc()
		return err
	}
	payload := map[string]any{
		"name":  c.config.ListName,
		"type":  "IPV4_ADDRESSES",
		"items": members,
	}
	method := http.MethodPost
	target := path
	for _, list := range lists {
		if list.Name == c.config.ListName {
			method = http.MethodPut
			target = path + "/" + list.ID
			break
		}
	}
	var result trafficMatchingList
	if err := c.do(ctx, method, target, payload, &result); err != nil {
		SyncFailures.Inc()
		return err
	}
	SyncTotal.Inc()
	GroupMembers.Set(float64(effectiveCount))
	return nil
}
