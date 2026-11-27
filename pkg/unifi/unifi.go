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
	"net/http"
	"strings"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

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
		http:   &http.Client{Transport: transport},
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
