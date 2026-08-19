package gpst

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// PreloginResponse represents the server's prelogin response.
type PreloginResponse struct {
	XMLName       xml.Name `xml:"prelogin-response"`
	Status        string   `xml:"status"`
	Message       string   `xml:"msg"`
	AuthMessage   string   `xml:"authentication-message"`
	UsernameLabel string   `xml:"username-label"`
	PasswordLabel string   `xml:"password-label"`
	SAMLMethod    string   `xml:"saml-auth-method"`
	SAMLRequest   string   `xml:"saml-request"`
	Region        string   `xml:"region"`
	LabelUserSign string   `xml:"saml-default-browser"`
}

// LoginResponse represents the JNLP-format gateway login response.
type LoginResponse struct {
	XMLName xml.Name `xml:"jnlp"`
	AppDesc struct {
		Arguments []string `xml:"argument"`
	} `xml:"application-desc"`
}

// AuthCookie holds the parsed authentication result.
type AuthCookie struct {
	AuthCookie       string
	PersistentCookie string
	Portal           string
	User             string
	Domain           string
	Computer         string
	PreferredIP      string

	// Raw cookie string for subsequent requests
	RawCookie string
}

// Client handles GlobalProtect protocol operations.
type Client struct {
	Server     string
	Username   string
	Password   string
	UserAgent  string
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// NewClient creates a new GlobalProtect client.
func NewClient(server, username, password string, insecure bool, logger *slog.Logger) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec // User-controlled option for self-signed certs
		},
	}
	return &Client{
		Server:    server,
		Username:  username,
		Password:  password,
		UserAgent: "PAN GlobalProtect",
		HTTPClient: &http.Client{
			Transport: transport,
		},
		Logger: logger,
	}
}

// Prelogin sends the prelogin request to get the authentication form.
func (c *Client) Prelogin() (*PreloginResponse, error) {
	reqURL := fmt.Sprintf("https://%s/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux", c.Server)

	c.Logger.Debug("sending prelogin request", "url", reqURL)

	req, err := http.NewRequest("POST", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating prelogin request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prelogin request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading prelogin response: %w", err)
	}

	c.Logger.Debug("prelogin response", "status", resp.StatusCode, "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prelogin returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var prelogin PreloginResponse
	if err := xml.Unmarshal(body, &prelogin); err != nil {
		return nil, fmt.Errorf("parsing prelogin XML: %w", err)
	}

	return &prelogin, nil
}

// Login performs gateway login and returns the auth cookie.
func (c *Client) Login() (*AuthCookie, error) {
	// First get the prelogin form
	prelogin, err := c.Prelogin()
	if err != nil {
		return nil, fmt.Errorf("prelogin: %w", err)
	}

	if prelogin.SAMLMethod != "" {
		return nil, fmt.Errorf("SAML authentication (%s) is not supported; use a prelogin-cookie instead", prelogin.SAMLMethod)
	}

	c.Logger.Info("prelogin successful", "message", prelogin.AuthMessage)

	// Submit login credentials
	loginURL := fmt.Sprintf("https://%s/ssl-vpn/login.esp", c.Server)

	form := url.Values{}
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("clientVer", "4100")
	form.Set("prot", "https:")
	form.Set("ipv6-support", "yes")
	form.Set("clientos", "Linux")
	form.Set("os-version", "linux")
	form.Set("server", c.Server)
	form.Set("computer", hostname())
	form.Set("user", c.Username)
	form.Set("passwd", c.Password)

	c.Logger.Debug("sending login request", "url", loginURL)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading login response: %w", err)
	}

	c.Logger.Debug("login response", "status", resp.StatusCode, "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return parseLoginResponse(body)
}

// LoginWithCookie performs login using a pre-existing cookie/token (e.g. from SAML).
func (c *Client) LoginWithCookie(cookieName, cookieValue string) (*AuthCookie, error) {
	loginURL := fmt.Sprintf("https://%s/ssl-vpn/login.esp", c.Server)

	form := url.Values{}
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("clientVer", "4100")
	form.Set("prot", "https:")
	form.Set("ipv6-support", "yes")
	form.Set("clientos", "Linux")
	form.Set("os-version", "linux")
	form.Set("server", c.Server)
	form.Set("computer", hostname())
	form.Set("user", c.Username)
	form.Set(cookieName, cookieValue)

	c.Logger.Debug("sending cookie-based login request", "url", loginURL)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return parseLoginResponse(body)
}

// parseLoginResponse parses the JNLP XML response from login.esp.
// The arguments are positional and map to specific fields.
func parseLoginResponse(body []byte) (*AuthCookie, error) {
	var loginResp LoginResponse
	if err := xml.Unmarshal(body, &loginResp); err != nil {
		// Check if this is an error response
		var errResp struct {
			XMLName xml.Name `xml:"response"`
			Status  string   `xml:"status,attr"`
			Error   string   `xml:"error"`
		}
		if err2 := xml.Unmarshal(body, &errResp); err2 == nil && errResp.Error != "" {
			return nil, fmt.Errorf("login failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("parsing login response: %w (body: %s)", err, string(body))
	}

	args := loginResp.AppDesc.Arguments

	// Arguments are positional per the openconnect source:
	// 0: unknown (usually empty)
	// 1: authcookie
	// 2: persistent-cookie
	// 3: portal
	// 4: user
	// 5: authentication-source
	// 6: configuration
	// 7: domain
	// 8-11: unknown (usually empty)
	// 12: connection-type (should be "tunnel")
	// 13: password-expiration-days
	// 14: clientVer (should be "4100")
	// 15: preferred-ip
	cookie := &AuthCookie{}

	get := func(i int) string {
		if i < len(args) {
			v := args[i]
			if v == "(null)" || v == "-1" || v == "" {
				return ""
			}
			return v
		}
		return ""
	}

	cookie.AuthCookie = get(1)
	cookie.PersistentCookie = get(2)
	cookie.Portal = get(3)
	cookie.User = get(4)
	cookie.Domain = get(7)
	cookie.PreferredIP = get(15)
	cookie.Computer = hostname()

	if cookie.AuthCookie == "" {
		return nil, fmt.Errorf("no authcookie in login response")
	}

	// Build raw cookie string for subsequent requests
	parts := []string{}
	addPart := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+url.QueryEscape(v))
		}
	}
	addPart("authcookie", cookie.AuthCookie)
	addPart("portal", cookie.Portal)
	addPart("user", cookie.User)
	addPart("domain", cookie.Domain)
	addPart("preferred-ip", cookie.PreferredIP)
	addPart("computer", cookie.Computer)
	cookie.RawCookie = strings.Join(parts, "&")

	return cookie, nil
}

// Logout sends a logout request to invalidate the session.
func (c *Client) Logout(cookie *AuthCookie) error {
	logoutURL := fmt.Sprintf("https://%s/ssl-vpn/logout.esp", c.Server)

	req, err := http.NewRequest("POST", logoutURL, strings.NewReader(cookie.RawCookie))
	if err != nil {
		return fmt.Errorf("creating logout request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading logout response: %w", err)
	}

	c.Logger.Debug("logout response", "status", resp.StatusCode, "body", string(body))
	return nil
}

func hostname() string {
	// Best-effort hostname
	h, _ := hostnameFn()
	if h == "" {
		h = "localhost"
	}
	return h
}

// Separated for testability
var hostnameFn = func() (string, error) {
	return osHostname()
}
