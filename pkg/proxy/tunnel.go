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
	"bypass-proxy/pkg/relay"
	"bypass-proxy/pkg/sni"
)

// Config contains runtime options for the proxy servers.
type Config struct {
	Resolver      *doh.Resolver
	SplitStrategy sni.SplitStrategy
	MicroDelay    time.Duration
	DialTimeout   time.Duration
	RelayWorker   string // Host of upstream Cloudflare Worker relay (e.g. bypass-relay.willson2016pos.workers.dev)
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
		cfg.MicroDelay = 15 * time.Millisecond
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 6 * time.Second
	}
	if cfg.RelayWorker == "" {
		cfg.RelayWorker = "bypass-relay.willson2016pos.workers.dev"
	}
	return &Tunnel{cfg: cfg}
}

// DialTarget resolves the host using DoH and dials a TCP connection.
// If target is IP-blackholed or direct dial fails, it routes through Cloudflare Worker relay.
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

	// 1. If target matches blackholed domain list, use Cloudflare Worker immediately
	if t.cfg.RelayWorker != "" && relay.IsBlackholeCandidate(host) {
		log.Printf("[Relay] Routing IP-blackholed target %s via Cloudflare Worker (%s)", target, t.cfg.RelayWorker)
		conn, err := relay.DialWS(ctx, t.cfg.Resolver, t.cfg.RelayWorker, target)
		if err == nil {
			return conn, nil
		}
		log.Printf("[Relay] Cloudflare Worker dial failed: %v, falling back to direct", err)
	}

	// 2. Direct connection with DoH resolution
	ip, err := t.cfg.Resolver.ResolveOne(ctx, host)
	if err != nil {
		ip = host
	}

	destAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		// 3. Fallback to Cloudflare Worker relay if direct dial fails
		if t.cfg.RelayWorker != "" {
			log.Printf("[Relay] Direct connection to %s failed (%v). Falling back to Cloudflare Worker relay...", target, err)
			relayConn, relayErr := relay.DialWS(ctx, t.cfg.Resolver, t.cfg.RelayWorker, target)
			if relayErr == nil {
				return relayConn, nil
			}
			return nil, fmt.Errorf("both direct (%v) and relay (%v) failed for %s", err, relayErr, target)
		}
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

	// Check if this connection is already tunneled through Cloudflare Worker relay
	_, isRelay := remoteConn.(*relay.WSConn)

	if !isRelay {
		// Direct connection through local ISP: apply SNI fragmentation
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
			if _, err := remoteConn.Write(clientData); err != nil {
				return fmt.Errorf("failed writing initial payload: %w", err)
			}
		}
	} else {
		// Remote connection outside Indonesia: write directly into WebSocket tunnel
		if _, err := remoteConn.Write(clientData); err != nil {
			return fmt.Errorf("failed writing initial payload to relay: %w", err)
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
