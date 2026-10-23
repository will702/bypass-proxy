package doh

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestResolver_DirectIP(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ip, err := r.ResolveOne(ctx, "1.1.1.1:443")
	if err != nil {
		t.Fatalf("unexpected error for direct IP: %v", err)
	}
	if ip != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1, got %s", ip)
	}
}

func TestResolver_ResolveDomain(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := r.Resolve(ctx, "one.one.one.one")
	if err != nil {
		t.Fatalf("failed to resolve domain: %v", err)
	}
	if len(ips) == 0 {
		t.Fatalf("no IPs returned")
	}

	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("invalid IP string: %s", ip)
		}
	}

	// Verify caching
	cachedIPs, err := r.Resolve(ctx, "one.one.one.one")
	if err != nil {
		t.Fatalf("failed cached lookup: %v", err)
	}
	if len(cachedIPs) != len(ips) {
		t.Fatalf("cache mismatch: got %v, expected %v", cachedIPs, ips)
	}
}
