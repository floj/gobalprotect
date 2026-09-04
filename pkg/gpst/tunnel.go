package gpst

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrAuthRejected indicates the gateway rejected the auth cookie when
// establishing the SSL tunnel. Callers should not retry with the same
// cookie; a fresh Login() is required.
var ErrAuthRejected = errors.New("gpst: auth cookie rejected by gateway")

// TunnelStats holds traffic statistics for the tunnel.
type TunnelStats struct {
	BytesSent     atomic.Int64
	BytesReceived atomic.Int64
	PacketsSent   atomic.Int64
	PacketsRecv   atomic.Int64
}

// Tunnel manages the SSL VPN tunnel connection.
type Tunnel struct {
	client *Client
	cookie *AuthCookie
	config *VPNConfig
	logger *slog.Logger

	Stats        TunnelStats
	DisableStats bool

	// ReadTimeout bounds how long a tunnel read may block without receiving
	// any data (including keepalive replies) before the connection is
	// considered dead. Must be greater than the keepalive interval.
	ReadTimeout time.Duration
	// KeepaliveInterval is the DPD send interval.
	KeepaliveInterval time.Duration

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

const (
	defaultReadTimeout       = 30 * time.Second
	defaultKeepaliveInterval = 10 * time.Second
)

// NewTunnel creates a new tunnel instance.
func NewTunnel(client *Client, cookie *AuthCookie, config *VPNConfig) *Tunnel {
	return &Tunnel{
		client: client,
		cookie: cookie,
		config: config,
		logger: client.Logger,
	}
}

// Connect establishes the SSL tunnel to the gateway.
func (t *Tunnel) Connect(ctx context.Context) error {
	t.logger.Info("connecting SSL tunnel", "server", t.client.Server)

	// Build the GET-tunnel request
	params := url.Values{}
	params.Set("user", t.cookie.User)
	params.Set("authcookie", t.cookie.AuthCookie)

	tunnelPath := strings.TrimPrefix(t.config.TunnelURL, "/")

	reqLine := fmt.Sprintf("GET /%s?%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",
		tunnelPath, params.Encode(), t.client.Server, t.client.UserAgent)

	// Establish raw TLS connection
	host := t.client.Server
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	var err error

	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return fmt.Errorf("TCP connect failed: %w", err)
	}

	tlsCfg := &tls.Config{
		ServerName: hostFromAddr(t.client.Server),
	}
	if tr, ok := t.client.HTTPClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		tlsCfg.InsecureSkipVerify = tr.TLSClientConfig.InsecureSkipVerify
	}

	tlsConn := tls.Client(rawConn, tlsCfg)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	conn = tlsConn

	// Send the GET-tunnel request
	t.logger.Debug("sending GET-tunnel request")
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		conn.Close()
		return fmt.Errorf("sending tunnel request: %w", err)
	}

	// Read the response - expect "START_TUNNEL"
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("reading tunnel response: %w", err)
	}

	response := string(buf[:n])
	if len(response) < 12 || response[:12] != "START_TUNNEL" {
		conn.Close()
		if isAuthRejection(response) {
			return fmt.Errorf("%w: %s", ErrAuthRejected, firstLine(response))
		}
		return fmt.Errorf("unexpected tunnel response: %s", response)
	}

	t.logger.Info("SSL tunnel established")
	if !t.setConn(conn) {
		conn.Close()
		return fmt.Errorf("tunnel closed")
	}
	return nil
}

// setConn atomically installs a new tunnel connection, closing any previous one.
// Returns false if the tunnel has already been closed by the caller.
func (t *Tunnel) setConn(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	if t.conn != nil {
		t.conn.Close()
	}
	t.conn = c
	return true
}

func (t *Tunnel) currentConn() net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}

// Read reads a packet from the tunnel.
// Returns the ethertype and payload data.
func (t *Tunnel) Read() (etherType uint16, payload []byte, err error) {
	c := t.currentConn()
	if c == nil {
		return 0, nil, fmt.Errorf("tunnel not connected")
	}
	return ReadPacket(c)
}

// Write writes a packet to the tunnel.
func (t *Tunnel) Write(payload []byte) error {
	c := t.currentConn()
	if c == nil {
		return fmt.Errorf("tunnel not connected")
	}
	pkt := EncodePacket(payload)
	_, err := c.Write(pkt)
	return err
}

// SendKeepalive sends a DPD/keepalive packet.
func (t *Tunnel) SendKeepalive() error {
	c := t.currentConn()
	if c == nil {
		return fmt.Errorf("tunnel not connected")
	}
	pkt := EncodeKeepalive()
	_, err := c.Write(pkt)
	return err
}

// Close closes the tunnel connection.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// RunDataLoop runs the bidirectional data loop between the tunnel and a TUN device
// for one session. tunRead reads packets from the TUN device, tunWrite writes
// packets to it. It returns when the tunnel connection dies or ctx is cancelled;
// callers are responsible for re-establishing the whole tunnel if they want to
// reconnect.
func (t *Tunnel) RunDataLoop(ctx context.Context, tunRead func() ([]byte, error), tunWrite func([]byte) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	readTimeout := t.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	keepalive := t.KeepaliveInterval
	if keepalive <= 0 {
		keepalive = defaultKeepaliveInterval
	}

	tunOut := make(chan []byte, 64)
	tunReadErr := make(chan error, 1)
	go func() {
		for {
			data, err := tunRead()
			if err != nil {
				select {
				case tunReadErr <- err:
				default:
				}
				return
			}
			if len(data) == 0 {
				continue
			}
			select {
			case tunOut <- data:
			case <-ctx.Done():
				return
			default:
				t.logger.Debug("tun send buffer full, dropping packet", "len", len(data))
			}
		}
	}()

	conn := t.currentConn()
	if conn == nil {
		return fmt.Errorf("tunnel not connected")
	}

	err := t.runSession(ctx, conn, tunOut, tunReadErr, tunWrite, readTimeout, keepalive)

	t.logger.Info("tunnel stats (final)",
		"sent_bytes", t.Stats.BytesSent.Load(),
		"recv_bytes", t.Stats.BytesReceived.Load(),
		"sent_packets", t.Stats.PacketsSent.Load(),
		"recv_packets", t.Stats.PacketsRecv.Load(),
	)
	return err
}

// runSession runs one connected session over conn. Returns when either
// direction fails or ctx is cancelled.
func (t *Tunnel) runSession(ctx context.Context, conn net.Conn, tunOut <-chan []byte, tunReadErr <-chan error, tunWrite func([]byte) error, readTimeout, keepalive time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 3)

	go func() { errCh <- t.readLoop(ctx, conn, tunWrite, readTimeout) }()
	go func() { errCh <- t.writeLoop(ctx, conn, tunOut) }()

	go func() {
		keepaliveTicker := time.NewTicker(keepalive)
		defer keepaliveTicker.Stop()

		statsTicker := time.NewTicker(1 * time.Minute)
		defer statsTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-keepaliveTicker.C:
				if _, err := conn.Write(EncodeKeepalive()); err != nil {
					errCh <- fmt.Errorf("keepalive write: %w", err)
					return
				}
				t.logger.Debug("sent keepalive")
			case <-statsTicker.C:
				if t.DisableStats {
					continue
				}
				t.logger.Info("tunnel stats",
					"sent_bytes", t.Stats.BytesSent.Load(),
					"recv_bytes", t.Stats.BytesReceived.Load(),
					"sent_packets", t.Stats.PacketsSent.Load(),
					"recv_packets", t.Stats.PacketsRecv.Load(),
				)
			}
		}
	}()

	select {
	case err := <-errCh:
		cancel()
		conn.Close()
		return err
	case err := <-tunReadErr:
		cancel()
		conn.Close()
		return fmt.Errorf("tun read failed: %w", err)
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}

func (t *Tunnel) readLoop(ctx context.Context, conn net.Conn, tunWrite func([]byte) error, readTimeout time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}

		etherType, payload, err := ReadPacket(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == io.EOF {
				return fmt.Errorf("tunnel closed by server")
			}
			return fmt.Errorf("reading from tunnel: %w", err)
		}

		switch etherType {
		case EtherTypeKeepalive:
			t.logger.Debug("received keepalive response")
			continue
		case EtherTypeIPv4, EtherTypeIPv6:
			if len(payload) == 0 {
				continue
			}
			t.Stats.BytesReceived.Add(int64(len(payload)))
			t.Stats.PacketsRecv.Add(1)
			if err := tunWrite(payload); err != nil {
				return fmt.Errorf("writing to TUN: %w", err)
			}
		default:
			t.logger.Warn("unknown ethertype in packet", "ethertype", fmt.Sprintf("0x%04x", etherType))
		}
	}
}

func (t *Tunnel) writeLoop(ctx context.Context, conn net.Conn, tunOut <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case data := <-tunOut:
			if len(data) == 0 {
				continue
			}
			t.Stats.BytesSent.Add(int64(len(data)))
			t.Stats.PacketsSent.Add(1)
			if _, err := conn.Write(EncodePacket(data)); err != nil {
				return fmt.Errorf("writing to tunnel: %w", err)
			}
		}
	}
}

func hostFromAddr(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// isAuthRejection heuristically detects an auth-rejection reply from the
// gateway to a GET-tunnel request. GlobalProtect gateways typically respond
// with an HTTP 401/403 status line (or a body containing "authentication"/
// "authcookie") when the auth cookie is invalid or expired.
func isAuthRejection(response string) bool {
	line := firstLine(response)
	upper := strings.ToUpper(line)
	if strings.HasPrefix(upper, "HTTP/") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[1] {
			case "401", "403":
				return true
			}
		}
	}
	lowerBody := strings.ToLower(response)
	if strings.Contains(lowerBody, "authentication") ||
		strings.Contains(lowerBody, "authcookie") ||
		strings.Contains(lowerBody, "unauthorized") ||
		strings.Contains(lowerBody, "forbidden") {
		return true
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
