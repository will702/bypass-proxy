package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"bypass-proxy/pkg/doh"
)

// WSConn wraps a TLS connection to a Cloudflare Worker providing a net.Conn over WebSocket binary frames.
type WSConn struct {
	tlsConn net.Conn
	reader  *bufio.Reader
	readBuf bytes.Buffer
	mu      sync.Mutex
}

// DialWS creates a WebSocket TCP tunnel to the specified target through the Cloudflare Worker.
func DialWS(ctx context.Context, resolver *doh.Resolver, workerHost, target string) (net.Conn, error) {
	// 1. Resolve Worker IP using DoH
	workerIP, err := resolver.ResolveOne(ctx, workerHost)
	if err != nil {
		workerIP = workerHost
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(workerIP, "443"))
	if err != nil {
		return nil, fmt.Errorf("failed to dial worker IP %s: %w", workerIP, err)
	}

	// 2. TLS Handshake to Worker
	tlsConfig := &tls.Config{
		ServerName:         workerHost,
		InsecureSkipVerify: false,
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("worker TLS handshake failed: %w", err)
	}

	// 3. WebSocket Upgrade Request
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	secKey := base64.StdEncoding.EncodeToString(nonce)

	reqPath := fmt.Sprintf("/tunnel?target=%s", target)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", reqPath, workerHost, secKey)

	if _, err := tlsConn.Write([]byte(req)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to send WS upgrade request: %w", err)
	}

	// 4. Parse Upgrade Response
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed reading upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("worker upgrade returned status %d (%s)", resp.StatusCode, resp.Status)
	}

	return &WSConn{
		tlsConn: tlsConn,
		reader:  br,
	}, nil
}

// Read decodes incoming WebSocket binary frames into client bytes.
func (c *WSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If buffer already has bytes, return them
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	// Read next WebSocket frame header
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return 0, err
	}

	opcode := header[0] & 0x0f
	if opcode == 0x08 { // Close frame
		return 0, io.EOF
	}

	isMasked := (header[1] & 0x80) != 0
	payloadLen := int64(header[1] & 0x7f)

	if payloadLen == 126 {
		var l uint16
		if err := binary.Read(c.reader, binary.BigEndian, &l); err != nil {
			return 0, err
		}
		payloadLen = int64(l)
	} else if payloadLen == 127 {
		var l uint64
		if err := binary.Read(c.reader, binary.BigEndian, &l); err != nil {
			return 0, err
		}
		payloadLen = int64(l)
	}

	var mask [4]byte
	if isMasked {
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return 0, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}

	if isMasked {
		for i := int64(0); i < payloadLen; i++ {
			payload[i] ^= mask[i%4]
		}
	}

	c.readBuf.Write(payload)
	return c.readBuf.Read(p)
}

// Write encodes outgoing client bytes into masked WebSocket binary frames.
func (c *WSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	var mask [4]byte
	_, _ = rand.Read(mask[:])

	var frame bytes.Buffer
	frame.WriteByte(0x82) // FIN + Binary frame

	l := len(p)
	if l <= 125 {
		frame.WriteByte(byte(0x80 | l))
	} else if l <= 65535 {
		frame.WriteByte(0x80 | 126)
		_ = binary.Write(&frame, binary.BigEndian, uint16(l))
	} else {
		frame.WriteByte(0x80 | 127)
		_ = binary.Write(&frame, binary.BigEndian, uint64(l))
	}

	frame.Write(mask[:])

	masked := make([]byte, l)
	for i := 0; i < l; i++ {
		masked[i] = p[i] ^ mask[i%4]
	}
	frame.Write(masked)

	_, err := c.tlsConn.Write(frame.Bytes())
	if err != nil {
		return 0, err
	}
	return l, nil
}

func (c *WSConn) Close() error {
	// Send close frame
	_, _ = c.tlsConn.Write([]byte{0x88, 0x80, 0, 0, 0, 0})
	return c.tlsConn.Close()
}

func (c *WSConn) LocalAddr() net.Addr                { return c.tlsConn.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr               { return c.tlsConn.RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error      { return c.tlsConn.SetDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error  { return c.tlsConn.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error { return c.tlsConn.SetWriteDeadline(t) }

// IsBlackholeCandidate checks if a host is known to have IP blackholing in Indonesia.
func IsBlackholeCandidate(host string) bool {
	h := strings.ToLower(host)
	keywords := []string{"pornhub", "phncdn", "xhamster", "xnxx", "xvideos", "youporn", "redtube", "brazzers", "onlyfans"}
	for _, kw := range keywords {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

// ErrDialDirectFailed indicates standard direct TCP dial failed.
var ErrDialDirectFailed = errors.New("direct connection failed")
