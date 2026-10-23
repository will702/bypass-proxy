package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"bypass-proxy/pkg/doh"
	"bypass-proxy/pkg/sni"
)

// generateTestCert creates an in-memory self-signed certificate for testing.
func generateTestCert(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Proxy Co"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	cert := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	// 1. Mock HTTPS Target Server
	targetListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start mock target: %v", err)
	}
	defer targetListener.Close()

	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong-through-proxy"))
	})
	targetServer := &http.Server{Handler: targetMux}
	go func() {
		_ = targetServer.Serve(targetListener)
	}()
	defer targetServer.Close()

	// 2. Start HTTP Proxy Server
	tunnel := NewTunnel(Config{
		Resolver:      doh.NewResolver(),
		SplitStrategy: sni.SplitAtSNI,
		MicroDelay:    1 * time.Millisecond,
	})

	proxyServer := NewHTTPServer("127.0.0.1:0", tunnel)
	go func() {
		_ = proxyServer.Start()
	}()
	defer proxyServer.Close()

	// Wait for proxy listener to bind
	for proxyServer.Addr() == nil {
		time.Sleep(10 * time.Millisecond)
	}

	proxyAddr := proxyServer.Addr().String()

	// 3. Make Client Request via Proxy
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := "https://" + targetListener.Addr().String() + "/ping"
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(body) != "pong-through-proxy" {
		t.Fatalf("expected 'pong-through-proxy', got '%s'", string(body))
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	// 1. Mock Echo TCP Server
	mockListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer mockListener.Close()

	go func() {
		for {
			conn, err := mockListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
			}(conn)
		}
	}()

	// 2. Start SOCKS5 Proxy
	tunnel := NewTunnel(Config{
		Resolver:      doh.NewResolver(),
		SplitStrategy: sni.SplitAtSNI,
		MicroDelay:    1 * time.Millisecond,
	})
	socksServer := NewSOCKS5Server("127.0.0.1:0", tunnel)
	go func() {
		_ = socksServer.Start()
	}()
	defer socksServer.Close()

	for socksServer.Addr() == nil {
		time.Sleep(10 * time.Millisecond)
	}

	// 3. Connect to SOCKS5 Server
	conn, err := net.Dial("tcp", socksServer.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial socks5: %v", err)
	}
	defer conn.Close()

	// SOCKS5 Handshake
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // VER 5, 1 method, NO AUTH
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected socks5 handshake response: %v", resp)
	}

	// Request CONNECT to mockListener
	tcpAddr := mockListener.Addr().(*net.TCPAddr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, tcpAddr.IP.To4()...)
	req = append(req, byte(tcpAddr.Port>>8), byte(tcpAddr.Port&0xff))
	_, _ = conn.Write(req)

	reply := make([]byte, 10)
	_, _ = io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("socks5 connect failed: reply code %d", reply[1])
	}

	// Send message
	_, _ = conn.Write([]byte("hello-socks"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed reading echo reply: %v", err)
	}

	if string(buf[:n]) != "echo:hello-socks" {
		t.Fatalf("unexpected echo response: %s", string(buf[:n]))
	}
}
