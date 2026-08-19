package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/floj/gobalprotect/gpst"
	"github.com/floj/gobalprotect/tun"
)

func main() {
	var (
		server       = flag.String("server", "", "GlobalProtect gateway address (required)")
		username     = flag.String("user", "", "Username (required for password auth)")
		password     = flag.String("passwd", "", "Password")
		cookieName   = flag.String("cookie-name", "", "Cookie/token field name for SAML auth (e.g. prelogin-cookie)")
		cookieValue  = flag.String("cookie-value", "", "Cookie/token value for SAML auth")
		insecure     = flag.Bool("insecure", false, "Skip TLS certificate verification")
		tunName      = flag.String("tun", "", "TUN device name (default: auto)")
		defaultRoute = flag.Bool("default-route", false, "Set default route through VPN tunnel")
		verbose      = flag.Bool("verbose", false, "Enable debug logging")
		noRoutes     = flag.Bool("no-routes", false, "Don't add split-tunnel routes from server config")
		noDNS        = flag.Bool("no-dns", false, "Don't configure DNS from server config")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "GlobalProtect VPN client using TUN device\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Password auth:\n")
		fmt.Fprintf(os.Stderr, "    %s -server vpn.example.com -user myuser -passwd mypass\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  SAML/cookie auth:\n")
		fmt.Fprintf(os.Stderr, "    %s -server vpn.example.com -user myuser -cookie-name prelogin-cookie -cookie-value TOKEN\n\n", os.Args[0])
	}

	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: -server is required")
		flag.Usage()
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	if err := run(context.Background(), logger, runConfig{
		server:       *server,
		username:     *username,
		password:     *password,
		cookieName:   *cookieName,
		cookieValue:  *cookieValue,
		insecure:     *insecure,
		tunName:      *tunName,
		defaultRoute: *defaultRoute,
		noRoutes:     *noRoutes,
		noDNS:        *noDNS,
	}); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

type runConfig struct {
	server       string
	username     string
	password     string
	cookieName   string
	cookieValue  string
	insecure     bool
	tunName      string
	defaultRoute bool
	noRoutes     bool
	noDNS        bool
}

func run(ctx context.Context, logger *slog.Logger, cfg runConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle signals for clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Create GP client
	client := gpst.NewClient(cfg.server, cfg.username, cfg.password, cfg.insecure, logger)
	client.InputCallback = func(prompt string) (string, error) {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("no input provided")
		}
		return strings.TrimSpace(scanner.Text()), nil
	}

	// Authenticate
	logger.Info("authenticating", "server", cfg.server, "user", cfg.username)
	var cookie *gpst.AuthCookie
	var err error

	if cfg.cookieName != "" && cfg.cookieValue != "" {
		cookie, err = client.LoginWithCookie(cfg.cookieName, cfg.cookieValue)
	} else {
		if cfg.username == "" {
			return fmt.Errorf("either -user/-passwd or -cookie-name/-cookie-value is required")
		}
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

	if !cfg.noRoutes {
		tunCfg.Routes = vpnConfig.SplitIncludes
	}
	if !cfg.noDNS {
		tunCfg.DNS = vpnConfig.DNS
	}

	tunDev, err := tun.New(tunCfg, logger)
	if err != nil {
		return fmt.Errorf("creating TUN device: %w", err)
	}
	defer func() {
		tunDev.RemoveDNS()
		tunDev.Close()
	}()

	// Set default route if requested
	if cfg.defaultRoute && vpnConfig.Gateway != "" {
		if err := tunDev.AddDefaultRoute(cfg.server); err != nil {
			logger.Warn("failed to add default route", "error", err)
		}
	}

	// Establish SSL tunnel
	tunnel := gpst.NewTunnel(client, cookie, vpnConfig)
	if err := tunnel.Connect(ctx); err != nil {
		return fmt.Errorf("tunnel connect: %w", err)
	}
	defer tunnel.Close()

	logger.Info("VPN tunnel active",
		"device", tunDev.Name(),
		"ip", vpnConfig.IPAddress,
		"dns", strings.Join(vpnConfig.DNS, ", "),
	)

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
