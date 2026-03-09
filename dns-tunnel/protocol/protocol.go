// Package protocol defines the wire format for the DNS tunnel.
//
// Upstream (client → server) — encoded in the DNS query QNAME:
//
//	<hex_data_labels...>.<seq4hex>.<sess8hex>.<cmd>.tunnel.site-tob.online.
//
//	cmd  : syn | dat | fin | pll (poll)
//	sess : 8-char hex = 4 random bytes (session ID)
//	seq  : 4-char hex = uint16 sequence number (unique per query → anti-cache)
//	data : hex-encoded payload, split into ≤62-char labels
//	       empty payload uses the placeholder label "0"
//
// Downstream (server → client) — encoded in DNS TXT records:
//
//	base64( [type:1][seq:2][ack:2][flags:1][len:2][payload...] )
//	split into ≤200-char TXT strings (DNS limit per string is 255 bytes)
//
//	type  : 0x01=SYNACK  0x02=DATA  0x03=FIN  0x04=ERR
//	flags : 0x01=FlagMore (more data buffered)  0x02=FlagClosed (upstream EOF)
package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Commands (embedded in QNAME label)
const (
	CmdSYN  = "syn"
	CmdDAT  = "dat"
	CmdFIN  = "fin"
	CmdPOLL = "pll"
)

// Response types
const (
	TypeSYNACK byte = 0x01
	TypeDATA   byte = 0x02
	TypeFIN    byte = 0x03
	TypeERR    byte = 0x04
)

// Response flags
const (
	FlagMore   byte = 0x01 // server has more buffered data — client should poll again immediately
	FlagClosed byte = 0x02 // upstream TCP connection is closed
)

const (
	HeaderSize       = 8   // bytes in the binary response header
	MaxUpstreamChunk = 100 // bytes per upstream DNS query payload
)

// Query represents a parsed upstream DNS query.
type Query struct {
	SessionID uint32
	SeqNum    uint16
	Cmd       string
	Payload   []byte
}

// Response represents data encoded in downstream DNS TXT records.
type Response struct {
	Type    byte
	SeqNum  uint16
	AckNum  uint16
	Flags   byte
	Payload []byte
}

// BuildQName returns the subdomain portion of the QNAME (without trailing dot,
// without the base domain).  Append ".<domain>." to get the full FQDN.
//
// Format: <hex_labels...>.<seq4>.<sess8>.<cmd>
func (q *Query) BuildQName() string {
	sess := fmt.Sprintf("%08x", q.SessionID)
	seq := fmt.Sprintf("%04x", q.SeqNum)

	payloadPart := "0"
	if len(q.Payload) > 0 {
		h := hex.EncodeToString(q.Payload)
		payloadPart = strings.Join(splitLabels(h, 62), ".")
	}

	return payloadPart + "." + seq + "." + sess + "." + q.Cmd
}

// ParseQName parses the subdomain portion (everything before ".<base_domain>.")
// back into a Query.
func ParseQName(subdomain string) (*Query, error) {
	parts := strings.Split(strings.ToLower(subdomain), ".")
	if len(parts) < 4 {
		return nil, fmt.Errorf("too few labels (%d)", len(parts))
	}

	n := len(parts)
	cmd := parts[n-1]
	switch cmd {
	case CmdSYN, CmdDAT, CmdFIN, CmdPOLL:
	default:
		return nil, fmt.Errorf("unknown command %q", cmd)
	}

	sessBytes, err := hex.DecodeString(parts[n-2])
	if err != nil || len(sessBytes) != 4 {
		return nil, fmt.Errorf("bad session id %q", parts[n-2])
	}

	seqBytes, err := hex.DecodeString(parts[n-3])
	if err != nil || len(seqBytes) != 2 {
		return nil, fmt.Errorf("bad seq %q", parts[n-3])
	}

	hexData := strings.Join(parts[:n-3], "")
	var payload []byte
	if hexData != "0" && len(hexData) > 0 {
		payload, err = hex.DecodeString(hexData)
		if err != nil {
			return nil, fmt.Errorf("bad hex payload: %v", err)
		}
	}

	return &Query{
		SessionID: binary.BigEndian.Uint32(sessBytes),
		SeqNum:    binary.BigEndian.Uint16(seqBytes),
		Cmd:       cmd,
		Payload:   payload,
	}, nil
}

// Encode serialises the Response into TXT strings (each ≤200 chars) that are
// base64-encoded.  The caller puts these into a single DNS TXT record.
func (r *Response) Encode() []string {
	data := make([]byte, HeaderSize+len(r.Payload))
	data[0] = r.Type
	binary.BigEndian.PutUint16(data[1:3], r.SeqNum)
	binary.BigEndian.PutUint16(data[3:5], r.AckNum)
	data[5] = r.Flags
	binary.BigEndian.PutUint16(data[6:8], uint16(len(r.Payload)))
	copy(data[8:], r.Payload)

	b64 := base64.StdEncoding.EncodeToString(data)
	return splitLabels(b64, 200)
}

// DecodeResponse reconstructs a Response from the TXT strings of a DNS answer.
func DecodeResponse(txts []string) (*Response, error) {
	b64 := strings.Join(txts, "")
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %v", err)
	}
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("data too short (%d bytes)", len(data))
	}

	payloadLen := binary.BigEndian.Uint16(data[6:8])
	if int(payloadLen) > len(data)-HeaderSize {
		return nil, fmt.Errorf("declared payload %d > available %d", payloadLen, len(data)-HeaderSize)
	}

	return &Response{
		Type:    data[0],
		SeqNum:  binary.BigEndian.Uint16(data[1:3]),
		AckNum:  binary.BigEndian.Uint16(data[3:5]),
		Flags:   data[5],
		Payload: data[8 : 8+payloadLen],
	}, nil
}

// splitLabels chops s into substrings of at most maxLen characters.
func splitLabels(s string, maxLen int) []string {
	var out []string
	for len(s) > maxLen {
		out = append(out, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}
