package splitdns

import (
	"time"

	"codeberg.org/miekg/dns"
	cache "github.com/go-pkgz/expirable-cache/v3"
)

// dnsCache is the interface used for DNS response caching.
type dnsCache interface {
	Get(key cacheKey) (*dns.Msg, bool)
	Set(key cacheKey, value *dns.Msg, ttl time.Duration)
}

// noopCache is a dnsCache that never stores or returns anything.
type noopCache struct{}

func (noopCache) Get(cacheKey) (*dns.Msg, bool)         { return nil, false }
func (noopCache) Set(cacheKey, *dns.Msg, time.Duration) {}

// lruCache wraps expirable-cache to implement dnsCache.
type lruCache struct {
	c cache.Cache[cacheKey, *dns.Msg]
}

func (l *lruCache) Get(key cacheKey) (*dns.Msg, bool) { return l.c.Get(key) }
func (l *lruCache) Set(key cacheKey, value *dns.Msg, ttl time.Duration) {
	l.c.Set(key, value, ttl)
}

// cacheKey is the key for DNS cache entries.
type cacheKey struct {
	name  string
	qtype uint16
}
