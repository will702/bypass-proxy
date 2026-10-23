package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPServer provides an HTTP/HTTPS forward proxy with DPI evasion on CONNECT tunnels.
type HTTPServer struct {
	addr     string
	tunnel   *Tunnel
	listener net.Listener
}

// NewHTTPServer creates an HTTP proxy instance.
func NewHTTPServer(addr string, tunnel *Tunnel) *HTTPServer {
	return &HTTPServer{
		addr:   addr,
		tunnel: tunnel,
	}
}

// Start begins listening and serving proxy requests.
func (s *HTTPServer) Start() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to bind HTTP proxy to %s: %w", s.addr, err)
	}
	return s.Serve(l)
}

// Serve accepts connections on the provided listener.
func (s *HTTPServer) Serve(l net.Listener) error {
	s.listener = l
	log.Printf("[HTTP Proxy] Listening on %s", l.Addr().String())

	for {
		conn, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Printf("[HTTP Proxy] Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Close terminates the listener.
func (s *HTTPServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the bound address.
func (s *HTTPServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *HTTPServer) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(clientConn, req)
	} else {
		s.handlePlainHTTP(clientConn, req)
	}
}

func (s *HTTPServer) handleConnect(clientConn net.Conn, req *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := req.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}

	remoteConn, err := s.tunnel.DialTarget(ctx, target)
	if err != nil {
		log.Printf("[HTTP CONNECT] Dial error for %s: %v", target, err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Send 200 Connection Established to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		remoteConn.Close()
		return
	}

	// Handshake interception & fragmented relay
	if err := s.tunnel.RelayHandshakeAndBridge(clientConn, remoteConn); err != nil {
		// Normal close or connection reset
	}
}

func (s *HTTPServer) handlePlainHTTP(clientConn net.Conn, req *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := req.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "80")
	}

	remoteConn, err := s.tunnel.DialTarget(ctx, target)
	if err != nil {
		log.Printf("[HTTP Plain] Dial error for %s: %v", target, err)
		resp := http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		_ = resp.Write(clientConn)
		return
	}
	defer remoteConn.Close()

	// Forward plain HTTP request
	if err := req.Write(remoteConn); err != nil {
		return
	}

	// Copy response back to client
	_, _ = io.Copy(clientConn, remoteConn)
}
