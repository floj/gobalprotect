package splitdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	cache "github.com/go-pkgz/expirable-cache/v3"
)

// RouteAdder is called with resolved IPs from split-domain DNS queries
// to dynamically add routes through the VPN tunnel.
type RouteAdder func(ip net.IP) error

// Server is a DNS proxy that resolves all queries via VPN DNS servers.
type Server struct {
	listenAddr string
	vpnDNS     []string
	logger     *slog.Logger
	server     *dns.Server
	client     *dns.Client
	routeAdder RouteAdder
	cache      dnsCache
}

// NewServer creates a new DNS server.
// vpnDNS are the DNS servers from the VPN config.
// routeAdder, if non-nil, is called for each resolved IP to add VPN routes.
// cacheSize sets the maximum number of cached DNS responses (0 disables caching).
func NewServer(listenAddr string, vpnDNS []string, logger *slog.Logger, routeAdder RouteAdder, cacheSize int) (*Server, error) {
	var c dnsCache = noopCache{}
	if cacheSize > 0 {
		c = &lruCache{cache.NewCache[cacheKey, *dns.Msg]().WithMaxKeys(cacheSize).WithLRU()}
	}

	return &Server{
		listenAddr: listenAddr,
		vpnDNS:     vpnDNS,
		logger:     logger,
		client:     dns.NewClient(),
		routeAdder: routeAdder,
		cache:      c,
	}, nil
}

// ListenAndServe starts the DNS server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.server = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleRequest),
	}
	s.logger.Info("starting DNS server", "addr", s.listenAddr, "vpn-dns", s.vpnDNS)
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the DNS server.
func (s *Server) Shutdown(ctx context.Context) {
	if s.server != nil {
		s.server.Shutdown(ctx)
	}
}

func (s *Server) handleRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	origID := r.ID

	qname := r.Question[0].Header().Name
	// dns names have trailing dot, strip it for matching
	name := strings.TrimSuffix(qname, ".")

	s.logger.Debug("dns query, using VPN DNS", "name", name, "upstream", s.vpnDNS)

	// Check cache
	qtype := dns.RRToType(r.Question[0])
	ck := cacheKey{name: qname, qtype: qtype}
	if cached, ok := s.cache.Get(ck); ok {
		s.logger.Debug("dns cache hit", "name", name, "type", qtype)
		resp := cached.Copy()
		resp.ID = r.ID
		resp.Data = nil
		resp.WriteTo(w)
		return
	}

	resp, err := s.forward(ctx, r, s.vpnDNS)
	if err != nil {
		s.logger.Warn("dns forward failed", "name", name, "error", err)
		// Send SERVFAIL
		fail := r.Copy()
		fail.Response = true
		fail.Rcode = dns.RcodeServerFailure
		fail.Data = nil
		fail.WriteTo(w)
		return
	}

	// Cache the response using the minimum TTL from the answer
	if ttl := minTTL(resp); ttl > 0 {
		s.cache.Set(ck, resp.Copy(), ttl)
		s.logger.Debug("dns cache store", "name", name, "type", qtype, "ttl", ttl)
	}

	// Add routes for resolved IPs
	if s.routeAdder != nil {
		s.addRoutesFromResponse(resp, name)
	}

	resp.ID = origID
	resp.Data = nil
	resp.WriteTo(w)
}

func (s *Server) addRoutesFromResponse(resp *dns.Msg, name string) {
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.Addr.AsSlice()
		case *dns.AAAA:
			ip = v.Addr.AsSlice()
		default:
			continue
		}
		if err := s.routeAdder(ip); err != nil {
			s.logger.Warn("failed to add route for DNS result", "name", name, "ip", ip, "error", err)
		}
	}
}

func (s *Server) forward(ctx context.Context, r *dns.Msg, upstreams []string) (*dns.Msg, error) {
	var lastErr error
	for _, srv := range upstreams {
		addr := ensurePort(srv, "53")
		resp, _, err := s.client.Exchange(ctx, r, "udp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all upstream DNS servers failed: %w", lastErr)
}

// minTTL returns the minimum TTL from all resource records in the response.
func minTTL(msg *dns.Msg) time.Duration {
	var min uint32
	for _, sections := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range sections {
			ttl := rr.Header().TTL
			if min == 0 || ttl < min {
				min = ttl
			}
		}
	}
	return time.Duration(min) * time.Second
}

func ensurePort(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// DomainMatcher matches domain names against split-tunneling patterns.
type DomainMatcher struct {
	exact    map[string]bool
	suffixes []string // stored as ".example.com" for suffix matching
}

// NewDomainMatcher creates a matcher from split-tunneling domain patterns.
// Patterns like "*.example.com" match any subdomain of example.com.
// Exact patterns like "app.example.com" match only that domain.
func NewDomainMatcher(patterns []string) *DomainMatcher {
	m := &DomainMatcher{
		exact: make(map[string]bool),
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			// *.example.com -> match anything ending in .example.com
			suffix := p[1:] // ".example.com"
			m.suffixes = append(m.suffixes, suffix)
			// Also match example.com itself (without subdomain)
			m.exact[p[2:]] = true
		} else {
			m.exact[p] = true
		}
	}
	return m
}

// Matches returns true if the domain matches any of the split-tunneling patterns.
func (m *DomainMatcher) Matches(domain string) bool {
	domain = strings.ToLower(domain)
	if m.exact[domain] {
		return true
	}
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}
