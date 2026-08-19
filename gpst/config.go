package gpst

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// VPNConfig holds the VPN configuration received from the gateway.
type VPNConfig struct {
	IPAddress   string
	Netmask     string
	MTU         int
	DNS         []string
	DNSSuffix   []string
	Gateway     string
	TunnelURL   string
	Lifetime    int
	IdleTimeout int
	Timeout     int // rekey interval

	SplitIncludes []string
	SplitExcludes []string
}

// configResponse is used for XML parsing of the getconfig response.
type configResponse struct {
	XMLName     xml.Name `xml:"response"`
	IPAddress   string   `xml:"ip-address"`
	Netmask     string   `xml:"netmask"`
	MTU         int      `xml:"mtu"`
	Lifetime    int      `xml:"lifetime"`
	IdleTimeout int      `xml:"disconnect-on-idle"`
	TunnelURL   string   `xml:"ssl-tunnel-url"`
	Timeout     int      `xml:"timeout"`
	GWAddress   string   `xml:"gw-address"`
	DNS         dnsBlock `xml:"dns"`
	DNSv6       dnsBlock `xml:"dns-v6"`
	DNSSuffix   struct {
		Members []string `xml:"member"`
	} `xml:"dns-suffix"`
	AccessRoutes struct {
		Members []string `xml:"member"`
	} `xml:"access-routes"`
	ExcludeRoutes struct {
		Members []string `xml:"member"`
	} `xml:"exclude-access-routes"`
}

type dnsBlock struct {
	Members []string `xml:"member"`
}

// GetConfig retrieves VPN configuration from the gateway.
func (c *Client) GetConfig(cookie *AuthCookie) (*VPNConfig, error) {
	configURL := fmt.Sprintf("https://%s/ssl-vpn/getconfig.esp", c.Server)

	form := url.Values{}
	form.Set("client-type", "1")
	form.Set("protocol-version", "p1")
	form.Set("app-version", "5.1.5-8")
	form.Set("clientos", "Linux")
	form.Set("os-version", "linux")
	form.Set("hmac-algo", "sha1,md5,sha256")
	form.Set("enc-algo", "aes-128-cbc,aes-256-cbc")

	// Append cookie fields
	form.Set("authcookie", cookie.AuthCookie)
	form.Set("portal", cookie.Portal)
	form.Set("user", cookie.User)
	form.Set("domain", cookie.Domain)
	form.Set("computer", cookie.Computer)
	if cookie.PreferredIP != "" {
		form.Set("preferred-ip", cookie.PreferredIP)
	}

	c.Logger.Debug("sending getconfig request", "url", configURL)

	req, err := http.NewRequest("POST", configURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating getconfig request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getconfig request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading getconfig response: %w", err)
	}

	c.Logger.Debug("getconfig response", "status", resp.StatusCode, "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getconfig returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return parseConfigResponse(body)
}

func parseConfigResponse(body []byte) (*VPNConfig, error) {
	// Check for error response first
	var errResp struct {
		XMLName xml.Name `xml:"response"`
		Status  string   `xml:"status,attr"`
		Error   string   `xml:"error"`
	}
	if err := xml.Unmarshal(body, &errResp); err == nil && errResp.Status == "error" {
		return nil, fmt.Errorf("getconfig error: %s", errResp.Error)
	}

	var cr configResponse
	if err := xml.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("parsing getconfig XML: %w", err)
	}

	if cr.IPAddress == "" {
		return nil, fmt.Errorf("no IP address in getconfig response")
	}

	cfg := &VPNConfig{
		IPAddress:     cr.IPAddress,
		Netmask:       cr.Netmask,
		MTU:           cr.MTU,
		Gateway:       cr.GWAddress,
		TunnelURL:     cr.TunnelURL,
		Lifetime:      cr.Lifetime,
		IdleTimeout:   cr.IdleTimeout,
		Timeout:       cr.Timeout,
		SplitIncludes: cr.AccessRoutes.Members,
		SplitExcludes: cr.ExcludeRoutes.Members,
	}

	if cfg.TunnelURL == "" {
		cfg.TunnelURL = "/ssl-tunnel-connect.sslvpn"
	}

	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}

	if cfg.Netmask == "" {
		cfg.Netmask = "255.255.255.255"
	}

	// Merge DNS from both v4 and v6
	seen := map[string]bool{}
	for _, d := range cr.DNS.Members {
		if d != "" && !seen[d] {
			cfg.DNS = append(cfg.DNS, d)
			seen[d] = true
		}
	}
	for _, d := range cr.DNSv6.Members {
		if d != "" && !seen[d] {
			cfg.DNS = append(cfg.DNS, d)
			seen[d] = true
		}
	}

	cfg.DNSSuffix = cr.DNSSuffix.Members

	return cfg, nil
}
