package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/manifoldco/promptui"
	cli "github.com/urfave/cli/v3"

	"github.com/floj/gobalprotect/pkg/gpst"
	"github.com/floj/gobalprotect/pkg/splitdns"
	"github.com/floj/gobalprotect/pkg/tun"
)

func connectCommand() *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "Connect to a GlobalProtect VPN gateway",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to YAML config file",
				Sources: cli.EnvVars("GP_CONFIG"),
			},
			&cli.StringFlag{
				Name:    "profile",
				Aliases: []string{"p"},
				Usage:   "Tunnel profile name from config file",
				Sources: cli.EnvVars("GP_PROFILE"),
			},
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Usage:   "GlobalProtect gateway address",
				Sources: cli.EnvVars("GP_SERVER"),
			},
			&cli.StringFlag{
				Name:    "username",
				Aliases: []string{"u"},
				Usage:   "Username (required for password auth)",
				Sources: cli.EnvVars("GP_USER"),
			},
			&cli.StringFlag{
				Name:    "password",
				Usage:   "Password",
				Sources: cli.EnvVars("GP_PASSWD"),
			},
			&cli.StringFlag{
				Name:    "password-cmd",
				Usage:   "Shell command to execute to obtain password (stdout is used, 10s timeout)",
				Sources: cli.EnvVars("GP_PASSWD_CMD"),
			},
			&cli.StringFlag{
				Name:    "cookie-name",
				Usage:   "Cookie/token field name for SAML auth (e.g. prelogin-cookie)",
				Sources: cli.EnvVars("GP_COOKIE_NAME"),
			},
			&cli.StringFlag{
				Name:    "cookie-value",
				Usage:   "Cookie/token value for SAML auth",
				Sources: cli.EnvVars("GP_COOKIE_VALUE"),
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Aliases: []string{"k"},
				Usage:   "Skip TLS certificate verification",
				Sources: cli.EnvVars("GP_INSECURE"),
			},
			&cli.StringFlag{
				Name:    "tun",
				Aliases: []string{"t"},
				Usage:   "TUN device name (default: auto)",
				Sources: cli.EnvVars("GP_TUN"),
			},
			&cli.BoolFlag{
				Name:    "default-route",
				Usage:   "Set default route through VPN tunnel",
				Sources: cli.EnvVars("GP_DEFAULT_ROUTE"),
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("GP_VERBOSE"),
			},
			&cli.BoolFlag{
				Name:    "log-json",
				Usage:   "Output logs in JSON format",
				Sources: cli.EnvVars("GP_LOG_JSON"),
			},
			&cli.BoolFlag{
				Name:    "no-routes",
				Usage:   "Don't add split-tunnel routes from server config",
				Sources: cli.EnvVars("GP_NO_ROUTES"),
			},
			&cli.BoolFlag{
				Name:    "no-dns",
				Usage:   "Don't configure DNS from server config",
				Sources: cli.EnvVars("GP_NO_DNS"),
			},
			&cli.StringFlag{
				Name:    "otp",
				Aliases: []string{"o"},
				Usage:   "OTP/MFA code to use for challenge response (skips interactive prompt)",
				Sources: cli.EnvVars("GP_OTP"),
			},
			&cli.StringFlag{
				Name:    "otp-cmd",
				Usage:   "Shell command to execute to obtain OTP (stdout is used as OTP, 10s timeout)",
				Sources: cli.EnvVars("GP_OTP_CMD"),
			},
			&cli.StringFlag{
				Name:    "totp-secret",
				Usage:   "Base32-encoded TOTP secret; OTP codes are generated from it on demand (also used during reconnect if --password is set)",
				Sources: cli.EnvVars("GP_TOTP_SECRET"),
			},
			&cli.StringFlag{
				Name:    "computer",
				Usage:   "Computer name to report to the gateway (default: auto-detect)",
				Sources: cli.EnvVars("GP_COMPUTER"),
			},
			&cli.BoolFlag{
				Name:    "no-serve-dns",
				Usage:   "Don't start a local DNS server for split-tunneling domains",
				Sources: cli.EnvVars("GP_NO_SERVE_DNS"),
			},
			&cli.IntFlag{
				Name:    "serve-dns-port",
				Usage:   "Port for the local DNS server",
				Value:   1553,
				Sources: cli.EnvVars("GP_SERVE_DNS_PORT"),
			},
			&cli.IntFlag{
				Name:    "dns-cache-size",
				Usage:   "Maximum number of cached DNS responses (0 to disable)",
				Value:   512,
				Sources: cli.EnvVars("GP_DNS_CACHE_SIZE"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// Load config file as base, flags/env override
			var fileCfg tunnelConfig
			if cfgPath := cmd.String("config"); cfgPath != "" {
				var err error
				fileCfg, err = loadConfigFile(cfgPath, cmd.String("profile"))
				if err != nil {
					return fmt.Errorf("loading config file: %w", err)
				}
			}

			logLevel := slog.LevelInfo
			if cmd.Bool("verbose") || fileCfg.Verbose {
				logLevel = slog.LevelDebug
			}
			var handler slog.Handler
			if cmd.Bool("log-json") || fileCfg.LogJSON {
				handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
			} else {
				handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
			}
			logger := slog.New(handler)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			sigCh := make(chan os.Signal, 2)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sigCh)
			go func() {
				select {
				case sig := <-sigCh:
					logger.Info("received signal, shutting down gracefully (press Ctrl+C again to force quit)", "signal", sig)
					cancel()
				case <-ctx.Done():
					return
				}
				select {
				case sig := <-sigCh:
					logger.Warn("received second signal, forcing exit", "signal", sig)
					os.Exit(130)
				case <-ctx.Done():
					return
				}
			}()

			username := coalesce(cmd.String("username"), fileCfg.Username)
			password := cmd.String("password")
			cookieName := coalesce(cmd.String("cookie-name"), fileCfg.CookieName)
			cookieValue := cmd.String("cookie-value")

			// Resolve password from command if password-cmd is set
			passwordCmd := coalesce(cmd.String("password-cmd"), fileCfg.PasswordCmd)
			if password == "" && passwordCmd != "" {
				pw, err := runShellCmd(ctx, passwordCmd)
				if err != nil {
					return fmt.Errorf("password-cmd failed: %w", err)
				}
				password = pw
				logger.Debug("obtained password from command", "cmd", passwordCmd, "password", strings.Repeat("*", len(password)))
			}

			// Resolve OTP from command if otp-cmd is set
			otp := cmd.String("otp")
			otpCmd := coalesce(cmd.String("otp-cmd"), fileCfg.OTPCmd)
			if otp == "" && otpCmd != "" {
				result, err := runShellCmd(ctx, otpCmd)
				if err != nil {
					return fmt.Errorf("otp-cmd failed: %w", err)
				}
				otp = result
				logger.Debug("obtained OTP from command", "cmd", otpCmd, "otp", otp)
			}

			totpSecret := coalesce(cmd.String("totp-secret"), fileCfg.TOTPSecret)

			if cookieName == "" || cookieValue == "" {
				if username == "" {
					prompt := promptui.Prompt{
						Label:     "Username",
						Stdout:    os.Stderr,
						Templates: promptTemplates(),
					}
					result, err := prompt.Run()
					if err != nil {
						return fmt.Errorf("username prompt failed: %w", err)
					}
					username = result
					if username == "" {
						return fmt.Errorf("either --username/--password or --cookie-name/--cookie-value is required")
					}
				}

				if password == "" {
					prompt := promptui.Prompt{
						Label:     "Password",
						Mask:      '*',
						Stdout:    os.Stderr,
						Templates: promptTemplates(),
					}
					result, err := prompt.Run()
					if err != nil {
						return fmt.Errorf("password prompt failed: %w", err)
					}
					password = result
				}
			}

			return run(ctx, logger, runConfig{
				server:         coalesce(cmd.String("server"), fileCfg.Server),
				username:       username,
				password:       password,
				cookieName:     cookieName,
				cookieValue:    cookieValue,
				insecure:       cmd.Bool("insecure") || fileCfg.Insecure,
				tunName:        coalesce(cmd.String("tun"), fileCfg.Tun),
				asDefaultRoute: cmd.Bool("default-route") || fileCfg.AsDefaultRoute,
				noRoutes:       cmd.Bool("no-routes") || fileCfg.NoRoutes,
				noDNS:          cmd.Bool("no-dns") || fileCfg.NoDNS,
				otp:            otp,
				totpSecret:     totpSecret,
				computer:       coalesce(cmd.String("computer"), fileCfg.Computer),
				noServeDNS:     cmd.Bool("no-serve-dns") || fileCfg.NoServeDNS,
				serveDNSPort:   coalesceInt(cmd.Int("serve-dns-port"), fileCfg.ServeDNSPort),
				dnsCacheSize:   coalesceInt(cmd.Int("dns-cache-size"), fileCfg.DNSCacheSize),
			})
		},
	}
}

type runConfig struct {
	server         string
	username       string
	password       string
	cookieName     string
	cookieValue    string
	insecure       bool
	tunName        string
	asDefaultRoute bool
	noRoutes       bool
	noDNS          bool
	otp            string
	totpSecret     string
	computer       string
	noServeDNS     bool
	serveDNSPort   int
	dnsCacheSize   int
}

type configFile struct {
	DefaultProfile string         `yaml:"default_profile"`
	Profiles       []tunnelConfig `yaml:"profiles"`
}

type tunnelConfig struct {
	Name           string `yaml:"name"`
	Server         string `yaml:"server"`
	Username       string `yaml:"username"`
	PasswordCmd    string `yaml:"password_cmd"`
	CookieName     string `yaml:"cookie_name"`
	Insecure       bool   `yaml:"insecure"`
	Tun            string `yaml:"tun"`
	AsDefaultRoute bool   `yaml:"as_default_route"`
	Verbose        bool   `yaml:"verbose"`
	LogJSON        bool   `yaml:"log_json"`
	NoRoutes       bool   `yaml:"no_routes"`
	NoDNS          bool   `yaml:"no_dns"`
	OTPCmd         string `yaml:"otp_cmd"`
	TOTPSecret     string `yaml:"totp_secret"`
	Computer       string `yaml:"computer"`
	NoServeDNS     bool   `yaml:"no_serve_dns"`
	ServeDNSPort   int    `yaml:"serve_dns_port"`
	DNSCacheSize   int    `yaml:"dns_cache_size"`
}

func loadConfigFile(path string, profile string) (tunnelConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tunnelConfig{}, err
	}
	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return tunnelConfig{}, err
	}

	if len(cfg.Profiles) == 0 {
		return tunnelConfig{}, fmt.Errorf("no tunnels defined in config file")
	}

	// Determine which tunnel to use
	name := profile
	if name == "" {
		name = cfg.DefaultProfile
	}

	// If only one tunnel defined, use it regardless of name
	if len(cfg.Profiles) == 1 {
		return cfg.Profiles[0], nil
	}

	if name == "" {
		return tunnelConfig{}, fmt.Errorf("multiple tunnels defined but no profile specified (use --profile or set default_profile in config)")
	}

	for _, t := range cfg.Profiles {
		if t.Name == name {
			return t, nil
		}
	}

	available := make([]string, len(cfg.Profiles))
	for i, t := range cfg.Profiles {
		available[i] = t.Name
	}
	return tunnelConfig{}, fmt.Errorf("profile %q not found in config (available: %s)", name, strings.Join(available, ", "))
}

func promptTemplates() *promptui.PromptTemplates {
	return &promptui.PromptTemplates{
		Prompt:  "{{ . }}: ",
		Valid:   "{{ . }}: ",
		Invalid: "{{ . }}: ",
		Success: "{{ . }}: ",
	}
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func coalesceInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func runShellCmd(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func run(ctx context.Context, logger *slog.Logger, cfg runConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create GP client
	client := gpst.NewClient(cfg.server, cfg.username, cfg.password, cfg.computer, cfg.insecure, logger)
	switch {
	case cfg.totpSecret != "":
		client.InputCallback = totpInputCallback(logger, cfg.totpSecret)
	case cfg.otp != "":
		var otpUsed atomic.Bool
		client.InputCallback = otpInputCallback(logger, cfg.otp, &otpUsed)
	default:
		client.InputCallback = interactiveInputCallback(ctx)
	}

	// Authenticate
	logger.Info("authenticating", "server", cfg.server, "user", cfg.username)
	var cookie *gpst.AuthCookie
	var err error

	if cfg.cookieName != "" && cfg.cookieValue != "" {
		cookie, err = client.LoginWithCookie(cfg.cookieName, cfg.cookieValue)
	} else {
		cookie, err = client.Login()
	}
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	logger.Info("authenticated successfully", "user", cookie.User, "portal", cookie.Portal)

	// Get VPN configuration
	vpnConfig, err := client.GetConfig(cookie)
	if err != nil {
		return fmt.Errorf("getting VPN config: %w", err)
	}

	logger.Info("VPN configuration received",
		"ip", vpnConfig.IPAddress,
		"netmask", vpnConfig.Netmask,
		"mtu", vpnConfig.MTU,
		"dns", vpnConfig.DNS,
		"gateway", vpnConfig.Gateway,
		"routes", vpnConfig.SplitIncludes,
	)

	// Create TUN device
	tunCfg := tun.Config{
		Name:    cfg.tunName,
		Address: vpnConfig.IPAddress,
		Netmask: vpnConfig.Netmask,
		MTU:     vpnConfig.MTU,
	}

	// Resolve VPN server IPs so we can exclude them from split routes
	serverIPs := resolveServerIPs(cfg.server, logger)
	tunCfg.ExcludeIPs = serverIPs

	if !cfg.noRoutes {
		tunCfg.Routes = vpnConfig.SplitIncludes
	}
	if !cfg.noDNS {
		tunCfg.DNS = []string{fmt.Sprintf("127.0.0.1:%d", cfg.serveDNSPort)}
		if cfg.noServeDNS {
			tunCfg.DNS = vpnConfig.DNS
		}
		tunCfg.DNSDomains = vpnConfig.SplitDomains
	}

	tunDev, err := tun.New(tunCfg, logger)
	if err != nil {
		return fmt.Errorf("creating TUN device: %w", err)
	}
	defer func() {
		tunDev.RemoveRoutes()
		tunDev.RemoveDNS()
		tunDev.Close()
	}()

	// Set default route if requested
	if cfg.asDefaultRoute && vpnConfig.Gateway != "" {
		if err := tunDev.AddDefaultRoute(cfg.server); err != nil {
			logger.Warn("failed to add default route", "error", err)
		}
	}

	// Establish SSL tunnel
	tunnel := gpst.NewTunnel(client, cookie, vpnConfig)
	if cfg.password != "" && cfg.totpSecret != "" {
		tunnel.Reauth = func(ctx context.Context) (*gpst.AuthCookie, error) {
			logger.Info("re-authenticating with saved password + TOTP secret")
			return client.Login()
		}
	}
	if err := tunnel.Connect(ctx); err != nil {
		return fmt.Errorf("tunnel connect: %w", err)
	}
	defer tunnel.Close()

	logger.Info("VPN tunnel active",
		"device", tunDev.Name(),
		"ip", vpnConfig.IPAddress,
		"dns", strings.Join(vpnConfig.DNS, ", "),
	)

	// Start DNS server unless disabled
	var dnsServer *splitdns.Server
	if !cfg.noServeDNS {
		serveDNSAddr := fmt.Sprintf("127.0.0.1:%d", cfg.serveDNSPort)
		dnsServer, err = splitdns.NewServer(serveDNSAddr, vpnConfig.DNS, logger, tunDev.AddRoute, cfg.dnsCacheSize)
		if err != nil {
			return fmt.Errorf("creating DNS server: %w", err)
		}
		for _, domain := range vpnConfig.SplitDomains {
			logger.Debug("DNS split domain", "domain", domain)
		}
		go func() {
			if err := dnsServer.ListenAndServe(); err != nil {
				logger.Error("DNS server failed", "error", err)
				cancel()
				return
			}
			logger.Info("DNS server stopped")
		}()
		defer dnsServer.Shutdown(ctx)
		logger.Info("DNS server started", "addr", serveDNSAddr)
	}

	tunnel.OnDisconnect = func() {
		logger.Info("clearing routes before reconnect")
		tunDev.RemoveRoutes()
		if dnsServer != nil {
			dnsServer.FlushCache()
		}
	}
	tunnel.OnReconnect = func() {
		logger.Info("reapplying routes after reconnect")
		tunDev.ReapplyRoutes()
	}

	go func() {
		<-ctx.Done()
		logger.Info("closing tunnel and shutting down gracefully")
	}()

	// Run the data loop
	err = tunnel.RunDataLoop(ctx, tunDev.Read, tunDev.Write)
	if err != nil && ctx.Err() != nil {
		// Clean shutdown via signal
		logger.Info("tunnel closed")

		// Attempt logout
		if logoutErr := client.Logout(cookie); logoutErr != nil {
			logger.Warn("logout failed", "error", logoutErr)
		} else {
			logger.Info("logged out successfully")
		}
		return nil
	}

	return err
}

func otpInputCallback(logger *slog.Logger, otp string, used *atomic.Bool) func(string) (string, error) {
	return func(prompt string) (string, error) {
		if !used.CompareAndSwap(false, true) {
			return "", fmt.Errorf("OTP already used, but server requested another challenge: %s", prompt)
		}
		logger.Info("using OTP from command line", "prompt", prompt, "otp", otp)
		return otp, nil
	}
}

func totpInputCallback(logger *slog.Logger, secret string) func(string) (string, error) {
	return func(prompt string) (string, error) {
		code, err := gpst.GenerateTOTP(secret)
		if err != nil {
			return "", fmt.Errorf("generating TOTP: %w", err)
		}
		logger.Info("generated TOTP from secret", "prompt", prompt)
		return code, nil
	}
}

func interactiveInputCallback(ctx context.Context) func(string) (string, error) {
	return func(prompt string) (string, error) {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			p := promptui.Prompt{
				Label:     prompt,
				Stdout:    os.Stderr,
				Templates: promptTemplates(),
			}
			result, err := p.Run()
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- result
		}()

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case err := <-errCh:
			return "", err
		case result := <-resultCh:
			return result, nil
		}
	}
}

// resolveServerIPs resolves the VPN server hostname to IP addresses.
func resolveServerIPs(server string, logger *slog.Logger) []string {
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}

	// If it's already an IP, return it directly
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		logger.Warn("could not resolve VPN server hostname", "host", host, "error", err)
		return nil
	}

	logger.Debug("resolved VPN server IPs", "host", host, "ips", addrs)
	return addrs
}
