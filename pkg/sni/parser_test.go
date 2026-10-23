package sni

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func generateClientHello(t *testing.T, serverName string) []byte {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	chData := make(chan []byte, 1)

	go func() {
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Errorf("failed to read from pipe: %v", err)
			chData <- nil
			return
		}
		chData <- buf[:n]
	}()

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}

	tlsClient := tls.Client(clientConn, tlsConfig)
	// Handshake will send ClientHello then block waiting for ServerHello
	go func() {
		_ = tlsClient.Handshake()
	}()

	select {
	case data := <-chData:
		if len(data) == 0 {
			t.Fatal("empty client hello received")
		}
		return data
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client hello")
		return nil
	}
}

func TestParseClientHello(t *testing.T) {
	rawCH := generateClientHello(t, "www.reddit.com")

	info, err := ParseClientHello(rawCH)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if !info.IsTLS {
		t.Errorf("expected IsTLS=true")
	}

	if info.ServerName != "www.reddit.com" {
		t.Errorf("expected ServerName='www.reddit.com', got '%s'", info.ServerName)
	}

	if info.SNIOffset <= 0 {
		t.Errorf("expected positive SNIOffset, got %d", info.SNIOffset)
	}

	// Verify that the slice at SNIOffset contains the actual domain string
	extractedDomain := string(rawCH[info.SNIOffset : info.SNIOffset+info.SNILength])
	if extractedDomain != "www.reddit.com" {
		t.Errorf("extracted domain mismatch: got '%s', expected 'www.reddit.com'", extractedDomain)
	}

	// Test split points calculation
	splitPoints := CalculateSplitPoints(rawCH, info, SplitAtSNI)
	if len(splitPoints) != 1 {
		t.Fatalf("expected 1 split point, got %d", len(splitPoints))
	}
	split := splitPoints[0]
	if split <= info.SNIOffset || split >= info.SNIOffset+info.SNILength {
		t.Errorf("expected split point (%d) to be strictly inside SNI range [%d, %d]",
			split, info.SNIOffset, info.SNIOffset+info.SNILength)
	}

	// Test multi-chunk split
	multiSplits := CalculateSplitPoints(rawCH, info, SplitMultiChunk)
	if len(multiSplits) != 2 {
		t.Fatalf("expected 2 split points for SplitMultiChunk, got %d", len(multiSplits))
	}

	// Test early split
	earlySplits := CalculateSplitPoints(rawCH, info, SplitEarly)
	if len(earlySplits) != 1 || earlySplits[0] != 30 {
		t.Fatalf("expected early split at byte 30, got %v", earlySplits)
	}
}

func TestWriteFragmented(t *testing.T) {
	rawCH := generateClientHello(t, "vimeo.com")
	info, err := ParseClientHello(rawCH)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	splitPoints := CalculateSplitPoints(rawCH, info, SplitAtSNI)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var received bytes.Buffer
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 1024)
		for received.Len() < len(rawCH) {
			n, err := serverConn.Read(buf)
			if err != nil {
				break
			}
			received.Write(buf[:n])
		}
		close(done)
	}()

	err = WriteFragmented(clientConn, rawCH, splitPoints, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("WriteFragmented failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading fragmented data")
	}

	if !bytes.Equal(rawCH, received.Bytes()) {
		t.Fatalf("recombined bytes do not match original ClientHello")
	}
}
