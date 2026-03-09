package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// SOCKS5 constants (RFC 1928)
const (
	socks5Ver     = 0x05
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypFQDN      = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repGenFailure = 0x01
)

// SOCKS5Server accepts browser connections and forwards each one through the
// DNS tunnel using a resolver chosen from the pool.
type SOCKS5Server struct {
	listenAddr string
	domain     string
	pool       *ResolverPool
}

// NewSOCKS5Server creates a SOCKS5 listener.
func NewSOCKS5Server(listenAddr, domain string, pool *ResolverPool) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: listenAddr, domain: domain, pool: pool}
}

// Run starts the listener and blocks until ctx is cancelled.
func (s *SOCKS5Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen on %s: %w", s.listenAddr, err)
	}

	log.Printf("SOCKS5 proxy listening on %s", s.listenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *SOCKS5Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// ── SOCKS5 handshake ────────────────────────────────────────────────────

	target, err := socks5Negotiate(conn)
	if err != nil {
		log.Printf("SOCKS5 handshake: %v", err)
		return
	}

	// ── Pick resolver (round-robin with health check) ───────────────────────

	resolver := s.pool.Pick()
	if resolver == nil {
		log.Printf("no resolver available, rejecting connection to %s", target)
		writeSocks5Reply(conn, repGenFailure)
		return
	}

	id := randSessionID()
	log.Printf("[%08x] new connection → %s (resolver: %s)", id, target, resolver.Addr)

	ts := newTunnelSession(id, resolver, s.domain, conn)

	// ── Establish tunnel (SYN / SYNACK) ────────────────────────────────────

	if err := ts.connect(ctx, target); err != nil {
		log.Printf("[%08x] tunnel connect: %v", id, err)
		writeSocks5Reply(conn, repGenFailure)
		return
	}

	// Tell the browser the connection succeeded.
	if err := writeSocks5Reply(conn, repSuccess); err != nil {
		log.Printf("[%08x] SOCKS5 reply: %v", id, err)
		return
	}

	// ── Data transfer ────────────────────────────────────────────────────────

	ts.transfer(ctx)
	log.Printf("[%08x] session closed", id)
}

// socks5Negotiate performs the SOCKS5 greeting + CONNECT request and returns
// the "host:port" target string.
func socks5Negotiate(conn net.Conn) (string, error) {
	// Greeting: VER + NMETHODS + METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != socks5Ver {
		return "", fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}
	// Choose "no authentication" (0x00).
	if _, err := conn.Write([]byte{socks5Ver, 0x00}); err != nil {
		return "", fmt.Errorf("send method choice: %w", err)
	}

	// Request: VER + CMD + RSV + ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}
	if req[0] != socks5Ver {
		return "", fmt.Errorf("request version mismatch: %d", req[0])
	}
	if req[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command 0x%02x (only CONNECT supported)", req[1])
	}

	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()

	case atypFQDN:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return "", err
		}
		name := make([]byte, lb[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)

	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = "[" + net.IP(b).String() + "]"

	default:
		return "", fmt.Errorf("unknown address type 0x%02x", req[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// writeSocks5Reply sends a SOCKS5 reply with the given REP code.
// BND.ADDR = 0.0.0.0, BND.PORT = 0.
func writeSocks5Reply(conn net.Conn, rep byte) error {
	reply := []byte{socks5Ver, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func randSessionID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
