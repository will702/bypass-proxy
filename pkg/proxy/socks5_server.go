package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// SOCKS5Server implements RFC 1928 SOCKS5 proxy protocol with SNI fragmentation.
type SOCKS5Server struct {
	addr     string
	tunnel   *Tunnel
	listener net.Listener
}

// NewSOCKS5Server creates a new SOCKS5 proxy server.
func NewSOCKS5Server(addr string, tunnel *Tunnel) *SOCKS5Server {
	return &SOCKS5Server{
		addr:   addr,
		tunnel: tunnel,
	}
}

// Start begins listening and serving SOCKS5 proxy requests.
func (s *SOCKS5Server) Start() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to bind SOCKS5 proxy to %s: %w", s.addr, err)
	}
	return s.Serve(l)
}

// Serve accepts connections on the provided listener.
func (s *SOCKS5Server) Serve(l net.Listener) error {
	s.listener = l
	log.Printf("[SOCKS5 Proxy] Listening on %s", l.Addr().String())

	for {
		conn, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Printf("[SOCKS5 Proxy] Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Close terminates the listener.
func (s *SOCKS5Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the bound address.
func (s *SOCKS5Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 1. Negotiation Handshake
	// Read VER and NMETHODS
	buf := make([]byte, 256)
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}

	if buf[0] != 0x05 { // SOCKS5 version
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	// Reply: version 5, NO AUTH (0x00)
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request Details
	// Read VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 0x01 { // CMD CONNECT
		// Command not supported
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(clientConn, buf[:domainLen]); err != nil {
			return
		}
		targetHost = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(clientConn, buf[:16]); err != nil {
			return
		}
		targetHost = net.IP(buf[:16]).String()
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Read Port
	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	remoteConn, err := s.tunnel.DialTarget(ctx, target)
	if err != nil {
		log.Printf("[SOCKS5] Dial error for %s: %v", target, err)
		// Host unreachable
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success reply: 0x05, 0x00 (success), 0x00, 0x01 (IPv4 0.0.0.0:0)
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		remoteConn.Close()
		return
	}

	// Relay handshake & bridge
	_ = s.tunnel.RelayHandshakeAndBridge(clientConn, remoteConn)
}
