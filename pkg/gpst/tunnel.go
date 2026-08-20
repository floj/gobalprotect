package gpst

import (
	"context"
	"crypto/tls"
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
	conn   net.Conn
	logger *slog.Logger

	Stats        TunnelStats
	DisableStats bool

	mu     sync.Mutex
	closed bool
}

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
		return fmt.Errorf("unexpected tunnel response: %s", response)
	}

	t.logger.Info("SSL tunnel established")
	t.conn = conn
	return nil
}

// Read reads a packet from the tunnel.
// Returns the ethertype and payload data.
func (t *Tunnel) Read() (etherType uint16, payload []byte, err error) {
	return ReadPacket(t.conn)
}

// Write writes a packet to the tunnel.
func (t *Tunnel) Write(payload []byte) error {
	pkt := EncodePacket(payload)
	_, err := t.conn.Write(pkt)
	return err
}

// SendKeepalive sends a DPD/keepalive packet.
func (t *Tunnel) SendKeepalive() error {
	pkt := EncodeKeepalive()
	_, err := t.conn.Write(pkt)
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

// RunDataLoop runs the bidirectional data loop between the tunnel and a TUN device.
// tunRead reads packets from the TUN device, tunWrite writes packets to it.
func (t *Tunnel) RunDataLoop(ctx context.Context, tunRead func() ([]byte, error), tunWrite func([]byte) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// Tunnel -> TUN (read from VPN, write to TUN)
	go func() {
		errCh <- t.readLoop(ctx, tunWrite)
	}()

	// TUN -> Tunnel (read from TUN, write to VPN)
	go func() {
		errCh <- t.writeLoop(ctx, tunRead)
	}()

	// Keepalive and stats loop
	go func() {
		keepaliveTicker := time.NewTicker(10 * time.Second)
		defer keepaliveTicker.Stop()

		statsTicker := time.NewTicker(1 * time.Minute)
		defer statsTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-keepaliveTicker.C:
				if err := t.SendKeepalive(); err != nil {
					t.logger.Warn("keepalive failed", "error", err)
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

	// Wait for first error
	err := <-errCh
	cancel()

	t.logger.Info("tunnel stats (final)",
		"sent_bytes", t.Stats.BytesSent.Load(),
		"recv_bytes", t.Stats.BytesReceived.Load(),
		"sent_packets", t.Stats.PacketsSent.Load(),
		"recv_packets", t.Stats.PacketsRecv.Load(),
	)

	return err
}

func (t *Tunnel) readLoop(ctx context.Context, tunWrite func([]byte) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		etherType, payload, err := t.Read()
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

func (t *Tunnel) writeLoop(ctx context.Context, tunRead func() ([]byte, error)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := tunRead()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("reading from TUN: %w", err)
		}

		if len(data) == 0 {
			continue
		}

		t.Stats.BytesSent.Add(int64(len(data)))
		t.Stats.PacketsSent.Add(1)
		if err := t.Write(data); err != nil {
			return fmt.Errorf("writing to tunnel: %w", err)
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
