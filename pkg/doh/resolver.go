package doh

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DNSResponse represents the JSON response returned by Cloudflare & Google DoH.
type DNSResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type cacheEntry struct {
	ips       []string
	expiresAt time.Time
}

// Resolver provides DNS resolution over HTTPS with in-memory caching and fallback.
type Resolver struct {
	client    *http.Client
	endpoints []string
	cache     map[string]cacheEntry
	mu        sync.RWMutex
}

// NewResolver initializes a DoH resolver with specified or default endpoints.
func NewResolver(endpoints ...string) *Resolver {
	if len(endpoints) == 0 {
		endpoints = []string{
			"https://1.1.1.1/dns-query",
			"https://1.0.0.1/dns-query",
			"https://8.8.8.8/resolve",
		}
	}

	// Custom transport configured to skip domain bootstrap resolution when connecting to DoH IPs.
	tr := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	return &Resolver{
		client: &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second,
		},
		endpoints: endpoints,
		cache:     make(map[string]cacheEntry),
	}
}

// Resolve returns the IP addresses for a given host (IPv4 preferred).
func (r *Resolver) Resolve(ctx context.Context, host string) ([]string, error) {
	// Strip port if present
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}

	// Check if host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}

	lowerHost := strings.ToLower(host)

	// Check cache
	r.mu.RLock()
	entry, found := r.cache[lowerHost]
	r.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.ips, nil
	}

	// Query DoH endpoints in order
	var lastErr error
	for _, endpoint := range r.endpoints {
		ips, minTTL, err := r.queryEndpoint(ctx, endpoint, lowerHost)
		if err == nil && len(ips) > 0 {
			if minTTL <= 0 {
				minTTL = 60
			}
			// Cap minTTL to reasonable bounds (30s to 1 hour)
			if minTTL < 30 {
				minTTL = 30
			} else if minTTL > 3600 {
				minTTL = 3600
			}

			r.mu.Lock()
			r.cache[lowerHost] = cacheEntry{
				ips:       ips,
				expiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
			}
			r.mu.Unlock()

			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("doh resolution failed for %s: %w", host, lastErr)
	}
	return nil, fmt.Errorf("doh resolution returned no addresses for %s", host)
}

// ResolveOne returns the first resolved IP or an error.
func (r *Resolver) ResolveOne(ctx context.Context, host string) (string, error) {
	ips, err := r.Resolve(ctx, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for %s", host)
	}
	return ips[0], nil
}

func (r *Resolver) queryEndpoint(ctx context.Context, endpoint, host string) ([]string, int, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}

	q := u.Query()
	q.Set("name", host)
	q.Set("type", "A")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("doh status %d: %s", resp.StatusCode, string(body))
	}

	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, 0, err
	}

	var ips []string
	minTTL := 300
	for _, ans := range dnsResp.Answer {
		if ans.Type == 1 { // Type A (IPv4)
			ips = append(ips, ans.Data)
			if ans.TTL > 0 && ans.TTL < minTTL {
				minTTL = ans.TTL
			}
		}
	}

	return ips, minTTL, nil
}
