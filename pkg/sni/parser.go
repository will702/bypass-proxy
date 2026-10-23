package sni

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// Info contains parsed information from a TLS ClientHello.
type Info struct {
	ServerName string
	SNIOffset  int // Starting byte index of the server name in the raw byte stream
	SNILength  int // Length of the server name string
	IsTLS      bool
}

// ErrNotClientHello is returned when the byte stream is not a TLS ClientHello.
var ErrNotClientHello = errors.New("not a valid TLS ClientHello")

// ParseClientHello parses the initial bytes from a connection to detect TLS ClientHello and SNI.
func ParseClientHello(data []byte) (*Info, error) {
	// Minimum TLS record (5) + ClientHello header (4) + minimum body (~40)
	if len(data) < 49 {
		return nil, ErrNotClientHello
	}

	// Byte 0: Record Type 0x16 (Handshake)
	// Byte 1-2: Protocol Version 0x03, 0x00..0x03
	if data[0] != 0x16 || data[1] != 0x03 {
		return nil, ErrNotClientHello
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen <= 0 {
		return nil, ErrNotClientHello
	}

	// Byte 5: Handshake Type 0x01 (ClientHello)
	if data[5] != 0x01 {
		return nil, ErrNotClientHello
	}

	// Handshake length (3 bytes)
	hsLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if hsLen <= 0 {
		return nil, ErrNotClientHello
	}

	// Offset starts at Handshake body (byte 9)
	// Skip Client Version (2 bytes) + Client Random (32 bytes) = 34 bytes
	pos := 9 + 34
	if pos >= len(data) {
		return nil, ErrNotClientHello
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return nil, ErrNotClientHello
	}

	// Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return nil, ErrNotClientHello
	}

	// Compression Methods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 > len(data) {
		return nil, ErrNotClientHello
	}

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	maxPos := pos + extensionsLen
	if maxPos > len(data) {
		maxPos = len(data)
	}

	// Iterate through extensions to find server_name (0x0000)
	for pos+4 <= maxPos {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // SNI
			if pos+extLen > maxPos {
				break
			}
			sniData := data[pos : pos+extLen]
			if len(sniData) > 5 {
				// server_name_list_length (2 bytes)
				// server_name_type (1 byte, 0 = host_name)
				nameType := sniData[2]
				if nameType == 0 {
					nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
					nameStartInSni := 5
					if nameStartInSni+nameLen <= len(sniData) {
						sniOffset := pos + nameStartInSni
						serverName := string(sniData[nameStartInSni : nameStartInSni+nameLen])
						return &Info{
							ServerName: serverName,
							SNIOffset:  sniOffset,
							SNILength:  nameLen,
							IsTLS:      true,
						}, nil
					}
				}
			}
		}
		pos += extLen
	}

	return &Info{
		ServerName: "",
		SNIOffset:  -1,
		SNILength:  0,
		IsTLS:      true,
	}, nil
}

// SplitStrategy dictates how the ClientHello is segmented across TCP packets.
type SplitStrategy int

const (
	// SplitEarly sends the first 30 bytes (Record Header + ClientRandom prefix) in segment 1, and the rest in segment 2.
	// This has proven to be the most reliable bypass across Indonesian ISP DPIs (avoids tiny-packet reassembly).
	SplitEarly SplitStrategy = iota
	// SplitAtSNI splits the ClientHello right in the middle of the SNI domain name.
	SplitAtSNI
	// SplitMultiChunk sends 3 chunks: first 30 bytes, middle of SNI, and remainder.
	SplitMultiChunk
)

// CalculateSplitPoints returns the byte boundaries where the buffer should be split into distinct TCP packets.
func CalculateSplitPoints(data []byte, info *Info, strategy SplitStrategy) []int {
	if !info.IsTLS || len(data) <= 10 {
		return nil
	}

	splitPrefix := 30
	if splitPrefix >= len(data) {
		splitPrefix = len(data) / 2
	}

	switch strategy {
	case SplitAtSNI:
		// Split in the middle of the SNI hostname
		if info.SNIOffset > 0 && info.SNILength > 1 {
			midSNI := info.SNIOffset + (info.SNILength / 2)
			if midSNI < len(data) {
				return []int{midSNI}
			}
		}
		return []int{splitPrefix}

	case SplitMultiChunk:
		// Segment 1: Record header + Random prefix (30 bytes)
		// Segment 2: Up to middle of SNI
		if info.SNIOffset > splitPrefix && info.SNILength > 1 {
			midSNI := info.SNIOffset + (info.SNILength / 2)
			if midSNI > splitPrefix && midSNI < len(data) {
				return []int{splitPrefix, midSNI}
			}
		}
		return []int{splitPrefix}

	case SplitEarly:
		fallthrough
	default:
		// Split at byte 30 (before session/cipher/SNI extensions)
		return []int{splitPrefix}
	}
}

// WriteFragmented writes data to the TCP connection split at the specified split points,
// disabling Nagle's algorithm and inserting a micro-delay to guarantee separate TCP packet emission.
func WriteFragmented(conn net.Conn, data []byte, splitPoints []int, delay time.Duration) error {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	if len(splitPoints) == 0 {
		_, err := conn.Write(data)
		return err
	}

	last := 0
	for _, pt := range splitPoints {
		if pt > last && pt < len(data) {
			chunk := data[last:pt]
			if _, err := conn.Write(chunk); err != nil {
				return err
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			last = pt
		}
	}

	if last < len(data) {
		chunk := data[last:]
		if _, err := conn.Write(chunk); err != nil {
			return err
		}
	}

	return nil
}
