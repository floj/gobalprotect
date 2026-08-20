package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	cli "github.com/urfave/cli/v3"

	"github.com/floj/gobalprotect/gpst"
	"github.com/floj/gobalprotect/tun"
)

func main() {
	cmd := &cli.Command{
		Name:  "gobalprotect",
		Usage: "GlobalProtect VPN client using TUN device",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "server",
				Usage:    "GlobalProtect gateway address",
				Required: true,
				Sources:  cli.EnvVars("GP_SERVER"),
			},
			&cli.StringFlag{
				Name:    "username",
				Usage:   "Username (required for password auth)",
				Sources: cli.EnvVars("GP_USER"),
			},
			&cli.StringFlag{
				Name:    "password",
				Usage:   "Password",
				Sources: cli.EnvVars("GP_PASSWD"),
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
				Usage:   "Skip TLS certificate verification",
				Sources: cli.EnvVars("GP_INSECURE"),
			},
			&cli.StringFlag{
				Name:    "tun",
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
				Usage:   "Enable debug logging",
				Sources: cli.EnvVars("GP_VERBOSE"),
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
				Usage:   "OTP/MFA code to use for challenge response (skips interactive prompt)",
				Sources: cli.EnvVars("GP_OTP"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			logLevel := slog.LevelInfo
			if cmd.Bool("verbose") {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			return run(ctx, logger, runConfig{
				server:       cmd.String("server"),
				username:     cmd.String("username"),
				password:     cmd.String("password"),
				cookieName:   cmd.String("cookie-name"),
				cookieValue:  cmd.String("cookie-value"),
				insecure:     cmd.Bool("insecure"),
				tunName:      cmd.String("tun"),
				defaultRoute: cmd.Bool("default-route"),
				noRoutes:     cmd.Bool("no-routes"),
				noDNS:        cmd.Bool("no-dns"),
				otp:          cmd.String("otp"),
			})
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
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
	otp          string
}

func run(ctx context.Context, logger *slog.Logger, cfg runConfig) error {

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create GP client
	client := gpst.NewClient(cfg.server, cfg.username, cfg.password, cfg.insecure, logger)
	if cfg.otp != "" {
		otpUsed := false
		client.InputCallback = func(prompt string) (string, error) {
			if otpUsed {
				return "", fmt.Errorf("OTP already used, but server requested another challenge: %s", prompt)
			}
			otpUsed = true
			logger.Info("using OTP from command line", "prompt", prompt)
			return cfg.otp, nil
		}
	} else {
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

	// Resolve VPN server IPs so we can exclude them from split routes
	serverIPs := resolveServerIPs(cfg.server, logger)
	tunCfg.ExcludeIPs = serverIPs

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
