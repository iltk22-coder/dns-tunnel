// Package server implements the authoritative DNS server side of the tunnel.
//
// Flow per tunnel session:
//  1. Client sends SYN → server dials target host via TCP.
//  2. Client sends DAT → server writes bytes to TCP conn; response carries
//     any buffered downstream bytes (piggyback).
//  3. Client sends PLL (poll) → response carries buffered downstream bytes.
//  4. A background goroutine continuously reads the TCP conn into downBuf.
//  5. Client sends FIN → server closes the TCP conn and removes the session.
package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dns-tunnel/protocol"
)

// Config holds server configuration.
type Config struct {
	ListenAddr  string        // e.g. "0.0.0.0:53"
	BaseDomain  string        // e.g. "tunnel.site-tob.online"
	ServerIP    string        // e.g. "138.124.3.221"  (for NS glue records)
	DialTimeout time.Duration // timeout for outbound TCP connections
	SessionTTL  time.Duration // idle sessions are cleaned up after this
}

// session holds per-connection state.
type session struct {
	mu      sync.Mutex
	conn    net.Conn
	downBuf bytes.Buffer  // downstream bytes waiting to be sent to client
	seen    map[uint16]bool // deduplicate upstream DAT packets by seq
	seq     uint16        // server-side sequence counter for responses
	closed  bool
	lastAt  time.Time
}

// Server is the DNS tunnel server.
type Server struct {
	cfg      Config
	sessions sync.Map // map[uint32]*session
}

// New creates a Server with the given configuration.
func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

// Run starts the UDP and TCP DNS listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	base := s.normalizedDomain()

	mux := dns.NewServeMux()
	mux.HandleFunc(base, s.handleDNS)

	// UDPSize: 4096 lets miekg/dns send responses larger than the default
	// 512-byte limit even when the incoming query has no EDNS0 OPT record.
	// Resolvers always support this; the 512-byte default is for end-user
	// legacy clients which never reach us directly.
	udp := &dns.Server{Addr: s.cfg.ListenAddr, Net: "udp", Handler: mux, UDPSize: 4096}
	tcp := &dns.Server{Addr: s.cfg.ListenAddr, Net: "tcp", Handler: mux}

	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()

	go s.cleanupLoop(ctx)

	log.Printf("DNS tunnel server listening on %s for zone %s", s.cfg.ListenAddr, base)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		udp.Shutdown()
		tcp.Shutdown()
		return nil
	}
}

// handleDNS is the miekg/dns handler for all queries in our zone.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	base := strings.TrimSuffix(s.normalizedDomain(), ".")

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = false
	msg.SetEdns0(4096, false)

	// ── Infrastructure records ──────────────────────────────────────────────

	if qname == base {
		switch q.Qtype {
		case dns.TypeSOA:
			msg.Answer = append(msg.Answer, s.soaRR(q.Name))
			w.WriteMsg(msg)
			return
		case dns.TypeNS:
			msg.Answer = append(msg.Answer, s.nsRRs(q.Name)...)
			w.WriteMsg(msg)
			return
		}
	}

	if (qname == "ns1."+base || qname == "ns2."+base) && q.Qtype == dns.TypeA {
		ip := net.ParseIP(s.cfg.ServerIP).To4()
		if ip != nil {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip,
			})
		}
		w.WriteMsg(msg)
		return
	}

	// ── Tunnel queries (must be TXT) ────────────────────────────────────────

	if q.Qtype != dns.TypeTXT {
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	// Strip base domain to get the subdomain we encoded.
	dotBase := "." + base
	if !strings.HasSuffix(qname, dotBase) {
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}
	subdomain := strings.TrimSuffix(qname, dotBase)

	pq, err := protocol.ParseQName(subdomain)
	if err != nil {
		log.Printf("parse error for %q: %v", subdomain, err)
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	resp, err := s.processQuery(pq)
	if err != nil {
		log.Printf("[%08x] %s error: %v", pq.SessionID, pq.Cmd, err)
		resp = &protocol.Response{Type: protocol.TypeERR}
	}

	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: resp.Encode(),
	})
	w.WriteMsg(msg)
}

// processQuery dispatches to the appropriate handler.
func (s *Server) processQuery(q *protocol.Query) (*protocol.Response, error) {
	switch q.Cmd {
	case protocol.CmdSYN:
		return s.handleSYN(q)
	case protocol.CmdDAT:
		return s.handleDAT(q)
	case protocol.CmdFIN:
		return s.handleFIN(q)
	case protocol.CmdPOLL:
		return s.handlePOLL(q)
	}
	return nil, fmt.Errorf("unknown command %q", q.Cmd)
}

func (s *Server) handleSYN(q *protocol.Query) (*protocol.Response, error) {
	target := string(q.Payload)

	// Idempotent: if the session already exists, just re-acknowledge.
	if v, ok := s.sessions.Load(q.SessionID); ok {
		sess := v.(*session)
		sess.mu.Lock()
		sess.lastAt = time.Now()
		sess.mu.Unlock()
		log.Printf("[%08x] SYN re-ack for %s", q.SessionID, target)
		return &protocol.Response{Type: protocol.TypeSYNACK, AckNum: q.SeqNum}, nil
	}

	log.Printf("[%08x] SYN → %s", q.SessionID, target)
	conn, err := net.DialTimeout("tcp", target, s.cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	sess := &session{
		conn:   conn,
		seen:   make(map[uint16]bool),
		lastAt: time.Now(),
	}
	s.sessions.Store(q.SessionID, sess)
	go s.readUpstream(q.SessionID, sess)

	return &protocol.Response{Type: protocol.TypeSYNACK, AckNum: q.SeqNum}, nil
}

func (s *Server) handleDAT(q *protocol.Query) (*protocol.Response, error) {
	sess, ok := s.getSession(q.SessionID)
	if !ok {
		return &protocol.Response{Type: protocol.TypeERR}, nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastAt = time.Now()

	// Deduplicate: drop packets we have already processed.
	if !sess.seen[q.SeqNum] {
		sess.seen[q.SeqNum] = true
		if len(sess.seen) > 2000 {
			sess.seen = map[uint16]bool{q.SeqNum: true}
		}
		if len(q.Payload) > 0 && !sess.closed {
			if _, err := sess.conn.Write(q.Payload); err != nil {
				sess.closed = true
				return s.buildResp(sess, q.SeqNum), nil
			}
		}
	}

	return s.buildResp(sess, q.SeqNum), nil
}

func (s *Server) handleFIN(q *protocol.Query) (*protocol.Response, error) {
	if v, ok := s.sessions.LoadAndDelete(q.SessionID); ok {
		sess := v.(*session)
		sess.mu.Lock()
		if !sess.closed {
			sess.closed = true
			sess.conn.Close()
		}
		sess.mu.Unlock()
		log.Printf("[%08x] FIN", q.SessionID)
	}
	return &protocol.Response{Type: protocol.TypeFIN}, nil
}

func (s *Server) handlePOLL(q *protocol.Query) (*protocol.Response, error) {
	sess, ok := s.getSession(q.SessionID)
	if !ok {
		return &protocol.Response{Type: protocol.TypeERR}, nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastAt = time.Now()

	return s.buildResp(sess, q.SeqNum), nil
}

// buildResp drains up to maxPayload bytes from downBuf and builds a response.
// Must be called with sess.mu held.
//
// maxPayload target: DNS message fits in a single unfragmented UDP packet.
//   500 bytes payload → 668 base64 chars → ~752 bytes total DNS message.
//   This fits in the 1232-byte EDNS0 size that resolvers use with auth servers.
//   FlagMore is set when downBuf still has data, so large responses are split
//   across multiple polls — each individually small.
func (s *Server) buildResp(sess *session, ack uint16) *protocol.Response {
	const maxPayload = 500

	sess.seq++
	resp := &protocol.Response{
		Type:   protocol.TypeDATA,
		SeqNum: sess.seq,
		AckNum: ack,
	}

	if n := sess.downBuf.Len(); n > 0 {
		size := n
		if size > maxPayload {
			size = maxPayload
		}
		payload := make([]byte, size)
		sess.downBuf.Read(payload)
		resp.Payload = payload

		if sess.downBuf.Len() > 0 {
			resp.Flags |= protocol.FlagMore
		}
	}

	if sess.closed {
		resp.Flags |= protocol.FlagClosed
	}
	return resp
}

// readUpstream runs in a goroutine; continuously reads from the upstream TCP
// connection and stores bytes in sess.downBuf.
func (s *Server) readUpstream(id uint32, sess *session) {
	buf := make([]byte, 8192)
	for {
		n, err := sess.conn.Read(buf)
		if n > 0 {
			sess.mu.Lock()
			sess.downBuf.Write(buf[:n])
			sess.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[%08x] upstream read: %v", id, err)
			}
			sess.mu.Lock()
			sess.closed = true
			sess.mu.Unlock()
			return
		}
	}
}

// cleanupLoop removes idle sessions every 30 seconds.
func (s *Server) cleanupLoop(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			now := time.Now()
			s.sessions.Range(func(k, v any) bool {
				sess := v.(*session)
				sess.mu.Lock()
				expired := now.Sub(sess.lastAt) > s.cfg.SessionTTL
				sess.mu.Unlock()
				if expired {
					sess.conn.Close()
					s.sessions.Delete(k)
					log.Printf("[%08x] session expired", k)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) getSession(id uint32) (*session, bool) {
	v, ok := s.sessions.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*session), true
}

// ── DNS infrastructure record helpers ───────────────────────────────────────

func (s *Server) normalizedDomain() string {
	d := strings.ToLower(s.cfg.BaseDomain)
	if !strings.HasSuffix(d, ".") {
		d += "."
	}
	return d
}

func (s *Server) soaRR(name string) dns.RR {
	base := s.normalizedDomain()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns1." + base,
		Mbox:    "hostmaster." + base,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  0,
	}
}

func (s *Server) nsRRs(name string) []dns.RR {
	base := s.normalizedDomain()
	return []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1." + base},
		&dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns2." + base},
	}
}
