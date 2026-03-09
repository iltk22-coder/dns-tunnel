package client

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"

	"dns-tunnel/protocol"
)

const (
	queryTimeout = 5 * time.Second
	maxRetries   = 3
	pollInterval = 50 * time.Millisecond // how often to poll when no upstream data
	upChanSize   = 64                    // buffered upstream chunks
)

// TunnelSession manages a single SOCKS5 connection tunnelled over DNS.
// One resolver is assigned per session; all DNS queries for this session
// go exclusively through that resolver (round-robin is per-connection).
type TunnelSession struct {
	id       uint32
	resolver *Resolver
	domain   string // base domain, e.g. "tunnel.site-tob.online"
	conn     net.Conn
	seq      uint16 // incremented for every outgoing DNS query
}

func newTunnelSession(id uint32, r *Resolver, domain string, conn net.Conn) *TunnelSession {
	return &TunnelSession{id: id, resolver: r, domain: domain, conn: conn}
}

// connect sends the SYN query and waits for SYNACK.
// Returns nil on success.
func (ts *TunnelSession) connect(ctx context.Context, target string) error {
	resp, err := ts.doQuery(ctx, &protocol.Query{
		SessionID: ts.id,
		SeqNum:    0,
		Cmd:       protocol.CmdSYN,
		Payload:   []byte(target),
	})
	if err != nil {
		return fmt.Errorf("SYN query: %w", err)
	}
	if resp.Type != protocol.TypeSYNACK {
		return fmt.Errorf("expected SYNACK, got type=0x%02x", resp.Type)
	}
	log.Printf("[%08x] tunnel connected to %s via %s", ts.id, target, ts.resolver.Addr)
	ts.seq = 1
	return nil
}

// transfer runs the bidirectional data loop.
// It blocks until the tunnel or the context ends.
func (ts *TunnelSession) transfer(ctx context.Context) {
	defer func() {
		// Best-effort FIN — ignore errors.
		ts.doQuery(ctx, &protocol.Query{ //nolint:errcheck
			SessionID: ts.id,
			Cmd:       protocol.CmdFIN,
		})
	}()

	// Read upstream (SOCKS5 conn → DNS) in a background goroutine.
	upCh := make(chan []byte, upChanSize)
	go func() {
		defer close(upCh)
		buf := make([]byte, protocol.MaxUpstreamChunk)
		for {
			n, err := ts.conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case upCh <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	needPollNow := false // set when server signals FlagMore

	for {
		if ctx.Err() != nil {
			return
		}

		var payload []byte
		var cmd string

		if needPollNow {
			// Server has more buffered data; don't wait for the timer.
			// But if there is upstream data ready, piggyback it.
			needPollNow = false
			select {
			case chunk, ok := <-upCh:
				if !ok {
					return
				}
				payload, cmd = chunk, protocol.CmdDAT
			default:
				cmd = protocol.CmdPOLL
			}
		} else {
			select {
			case chunk, ok := <-upCh:
				if !ok {
					return // upstream EOF
				}
				payload, cmd = chunk, protocol.CmdDAT
			case <-time.After(pollInterval):
				cmd = protocol.CmdPOLL
			case <-ctx.Done():
				return
			}
		}

		q := &protocol.Query{
			SessionID: ts.id,
			SeqNum:    ts.seq,
			Cmd:       cmd,
			Payload:   payload,
		}
		ts.seq++

		resp, err := ts.doQuery(ctx, q)
		if err != nil {
			log.Printf("[%08x] query error: %v", ts.id, err)
			// Don't stop — keep retrying on transient errors.
			continue
		}

		if len(resp.Payload) > 0 {
			if _, err := ts.conn.Write(resp.Payload); err != nil {
				if err != io.EOF {
					log.Printf("[%08x] write to SOCKS5 conn: %v", ts.id, err)
				}
				return
			}
		}

		if resp.Type == protocol.TypeFIN || resp.Flags&protocol.FlagClosed != 0 {
			return
		}

		needPollNow = resp.Flags&protocol.FlagMore != 0
	}
}

// doQuery sends one DNS TXT query and parses the TXT response.
// Tries UDP first; falls back to TCP automatically if the response is
// truncated (TC bit set). Retries up to maxRetries times on errors.
func (ts *TunnelSession) doQuery(ctx context.Context, q *protocol.Query) (*protocol.Response, error) {
	qname := q.BuildQName() + "." + ts.domain + "."

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeTXT)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	udpClient := &dns.Client{Net: "udp", Timeout: queryTimeout}
	tcpClient := &dns.Client{Net: "tcp", Timeout: queryTimeout}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		t0 := time.Now()
		resp, _, err := udpClient.ExchangeContext(ctx, msg, ts.resolver.Addr)
		if err != nil {
			lastErr = err
			ts.resolver.RecordFailure()
			log.Printf("[%08x] DNS UDP attempt %d/%d failed: %v", ts.id, attempt+1, maxRetries, err)
			continue
		}

		// UDP response was truncated — retry the same query over TCP.
		if resp.Truncated {
			log.Printf("[%08x] DNS response truncated, retrying over TCP", ts.id)
			resp, _, err = tcpClient.ExchangeContext(ctx, msg, ts.resolver.Addr)
			if err != nil {
				lastErr = err
				ts.resolver.RecordFailure()
				log.Printf("[%08x] DNS TCP fallback failed: %v", ts.id, err)
				continue
			}
		}

		ts.resolver.RecordSuccess(time.Since(t0))

		// Empty answer → server has no downstream data yet.
		if len(resp.Answer) == 0 {
			return &protocol.Response{Type: protocol.TypeDATA}, nil
		}

		for _, rr := range resp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				return protocol.DecodeResponse(txt.Txt)
			}
		}
		return &protocol.Response{Type: protocol.TypeDATA}, nil
	}

	return nil, fmt.Errorf("all %d retries failed (last: %v)", maxRetries, lastErr)
}
