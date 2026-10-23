package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"bypass-proxy/pkg/doh"
	"bypass-proxy/pkg/sni"
)

// Config contains runtime options for the proxy servers.
type Config struct {
	Resolver      *doh.Resolver
	SplitStrategy sni.SplitStrategy
	MicroDelay    time.Duration
	DialTimeout   time.Duration
}

// Tunnel handles connecting to remote targets and applying DPI-evasion techniques.
type Tunnel struct {
	cfg Config
}

// NewTunnel creates a new Tunnel instance.
func NewTunnel(cfg Config) *Tunnel {
	if cfg.Resolver == nil {
		cfg.Resolver = doh.NewResolver()
	}
	if cfg.MicroDelay <= 0 {
		cfg.MicroDelay = 5 * time.Millisecond
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &Tunnel{cfg: cfg}
}

// DialTarget resolves the host using DoH and dials a TCP connection.
func (t *Tunnel) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %s: %w", portStr, err)
	}

	ip, err := t.cfg.Resolver.ResolveOne(ctx, host)
	if err != nil {
		// Fallback to standard resolver if DoH fails
		ip = host
	}

	destAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{
		Timeout: t.cfg.DialTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s (%s): %w", target, destAddr, err)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}

// RelayHandshakeAndBridge intercepts the initial packet from client, fragments it if TLS, and bridges the streams.
func (t *Tunnel) RelayHandshakeAndBridge(clientConn, remoteConn net.Conn) error {
	defer clientConn.Close()
	defer remoteConn.Close()

	// Read initial buffer from client (expecting TLS ClientHello or initial request)
	initialBuf := make([]byte, 4096)
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := clientConn.Read(initialBuf)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("failed to read initial handshake from client: %w", err)
	}

	clientData := initialBuf[:n]

	// Check if this is a TLS ClientHello
	info, err := sni.ParseClientHello(clientData)
	if err == nil && info.IsTLS {
		splitPoints := sni.CalculateSplitPoints(clientData, info, t.cfg.SplitStrategy)
		if len(splitPoints) > 0 {
			if err := sni.WriteFragmented(remoteConn, clientData, splitPoints, t.cfg.MicroDelay); err != nil {
				return fmt.Errorf("failed writing fragmented ClientHello: %w", err)
			}
		} else {
			if _, err := remoteConn.Write(clientData); err != nil {
				return fmt.Errorf("failed writing ClientHello: %w", err)
			}
		}
	} else {
		// Non-TLS initial packet, write as-is
		if _, err := remoteConn.Write(clientData); err != nil {
			return fmt.Errorf("failed writing initial payload: %w", err)
		}
	}

	// Bidirectional stream copying
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn, dir string) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}

	go pipe(remoteConn, clientConn, "client->remote")
	go pipe(clientConn, remoteConn, "remote->client")

	wg.Wait()
	return nil
}

// ParseHostPort ensures a host string has a port, defaulting to 80 or 443.
func ParseHostPort(addr string, defaultPort int) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	return fmt.Sprintf("%s:%d", addr, defaultPort)
}

// LogDebug logs debug output if verbose logging is enabled.
func LogDebug(format string, v ...interface{}) {
	log.Printf("[DEBUG] "+format, v...)
}
