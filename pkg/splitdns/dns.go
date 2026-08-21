package splitdns

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	cache "github.com/go-pkgz/expirable-cache/v3"
)

// RouteAdder is called with resolved IPs from split-domain DNS queries
// to dynamically add routes through the VPN tunnel.
type RouteAdder func(ip net.IP) error

// Server is a DNS proxy that resolves matching domains via VPN DNS servers
// and forwards everything else to the system's resolv.conf DNS servers.
type Server struct {
	listenAddr    string
	vpnDNS        []string
	systemDNS     []string
	domainMatcher *DomainMatcher
	logger        *slog.Logger
	server        *dns.Server
	routeAdder    RouteAdder
	cache         dnsCache
}

// NewServer creates a new DNS server.
// vpnDNS are the DNS servers from the VPN config.
// splitDomains are the include-split-tunneling-domain patterns (supports leading wildcard like *.example.com).
// routeAdder, if non-nil, is called for each resolved IP from split-domain queries to add VPN routes.
// cacheSize sets the maximum number of cached DNS responses (0 disables caching).
func NewServer(listenAddr string, vpnDNS []string, splitDomains []string, logger *slog.Logger, routeAdder RouteAdder, cacheSize int) (*Server, error) {
	systemDNS, err := readResolvConf()
	if err != nil {
		return nil, fmt.Errorf("reading resolv.conf: %w", err)
	}
	if len(systemDNS) == 0 {
		return nil, fmt.Errorf("no nameservers found in resolv.conf")
	}

	matcher := NewDomainMatcher(splitDomains)

	var c dnsCache = noopCache{}
	if cacheSize > 0 {
		c = &lruCache{cache.NewCache[cacheKey, *dns.Msg]().WithMaxKeys(cacheSize).WithLRU()}
	}

	return &Server{
		listenAddr:    listenAddr,
		vpnDNS:        vpnDNS,
		systemDNS:     systemDNS,
		domainMatcher: matcher,
		logger:        logger,
		routeAdder:    routeAdder,
		cache:         c,
	}, nil
}

// ListenAndServe starts the DNS server. It blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.server = &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleRequest),
	}
	s.logger.Info("starting DNS server", "addr", s.listenAddr, "vpn-dns", s.vpnDNS, "system-dns", s.systemDNS)
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the DNS server.
func (s *Server) Shutdown(ctx context.Context) {
	if s.server != nil {
		s.server.Shutdown(ctx)
	}
}

func (s *Server) handleRequest(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if err := r.Unpack(); err != nil {
		s.logger.Warn("dns unpack failed", "error", err)
		return
	}

	if len(r.Question) == 0 {
		return
	}

	qname := r.Question[0].Header().Name
	// dns names have trailing dot, strip it for matching
	name := strings.TrimSuffix(qname, ".")

	var upstream []string
	matched := s.domainMatcher.Matches(name)
	if matched {
		upstream = s.vpnDNS
		s.logger.Debug("dns query matched split domain, using VPN DNS", "name", name, "upstream", upstream)
	} else {
		upstream = s.systemDNS
		s.logger.Debug("dns query not matched, using system DNS", "name", name, "upstream", upstream)
	}

	// Check cache
	qtype := dns.RRToType(r.Question[0])
	ck := cacheKey{name: qname, qtype: qtype}
	if cached, ok := s.cache.Get(ck); ok {
		s.logger.Debug("dns cache hit", "name", name, "type", qtype)
		resp := cached.Copy()
		resp.ID = r.ID
		resp.WriteTo(w)
		return
	}

	resp, err := s.forward(r, upstream)
	if err != nil {
		s.logger.Warn("dns forward failed", "name", name, "error", err)
		// Send SERVFAIL
		fail := r.Copy()
		fail.Response = true
		fail.Rcode = dns.RcodeServerFailure
		fail.WriteTo(w)
		return
	}

	// Cache the response using the minimum TTL from the answer
	if ttl := minTTL(resp); ttl > 0 {
		s.cache.Set(ck, resp.Copy(), ttl)
		s.logger.Debug("dns cache store", "name", name, "type", qtype, "ttl", ttl)
	}

	// Add routes for resolved IPs from split-domain queries
	if matched && s.routeAdder != nil {
		s.addRoutesFromResponse(resp, name)
	}

	resp.ID = r.ID
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

func (s *Server) forward(r *dns.Msg, upstreams []string) (*dns.Msg, error) {
	c := dns.NewClient()
	var lastErr error
	for _, srv := range upstreams {
		addr := ensurePort(srv, "53")
		resp, _, err := c.Exchange(context.Background(), r, "udp", addr)
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

// readResolvConf reads nameservers from /etc/resolv.conf.
func readResolvConf() ([]string, error) {
	return readResolvConfFile("/etc/resolv.conf")
}

func readResolvConfFile(path string) ([]string, error) {
	// Resolve symlinks to handle systemd-resolved stub
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		path = resolved
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return servers, scanner.Err()
}
