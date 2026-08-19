package tun

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

// Device represents a TUN network device.
type Device struct {
	iface  *water.Interface
	name   string
	logger *slog.Logger
}

// Config holds the TUN device configuration.
type Config struct {
	Name       string // e.g. "gpd0"; empty for auto
	Address    string // e.g. "10.0.0.1"
	Netmask    string // e.g. "255.255.255.255"
	MTU        int
	DNS        []string
	Routes     []string // CIDR routes to add, e.g. "10.0.0.0/8"
	ExcludeIPs []string // IPs to route via existing default gateway (e.g. VPN server)
}

// New creates and configures a new TUN device.
func New(cfg Config, logger *slog.Logger) (*Device, error) {
	wcfg := water.Config{
		DeviceType: water.TUN,
	}
	if cfg.Name != "" {
		wcfg.Name = cfg.Name
	}

	iface, err := water.New(wcfg)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device: %w", err)
	}

	dev := &Device{
		iface:  iface,
		name:   iface.Name(),
		logger: logger,
	}

	logger.Info("TUN device created", "name", dev.name)

	if err := dev.configure(cfg); err != nil {
		iface.Close()
		return nil, fmt.Errorf("configuring TUN device: %w", err)
	}

	return dev, nil
}

// Name returns the device name.
func (d *Device) Name() string {
	return d.name
}

// Read reads a packet from the TUN device.
func (d *Device) Read() ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := d.iface.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Write writes a packet to the TUN device.
func (d *Device) Write(data []byte) error {
	_, err := d.iface.Write(data)
	return err
}

// Close closes the TUN device.
func (d *Device) Close() error {
	d.logger.Info("closing TUN device", "name", d.name)
	return d.iface.Close()
}

func (d *Device) configure(cfg Config) error {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1400
	}

	// Compute peer address for point-to-point link
	peerAddr := cfg.Address

	// Set IP address and bring up interface
	if err := run("ip", "addr", "add", cfg.Address+"/32", "peer", peerAddr, "dev", d.name); err != nil {
		return fmt.Errorf("setting IP address: %w", err)
	}

	if err := run("ip", "link", "set", "dev", d.name, "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
		return fmt.Errorf("setting MTU and bringing up interface: %w", err)
	}

	d.logger.Info("TUN device configured", "address", cfg.Address, "mtu", mtu)

	// Add host routes for excluded IPs (e.g. VPN server) via existing default gateway
	// to prevent routing loops when split routes cover the VPN server's IP.
	if len(cfg.ExcludeIPs) > 0 {
		if gw := detectDefaultGateway(); gw != "" {
			for _, ip := range cfg.ExcludeIPs {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					continue
				}
				if err := run("ip", "route", "add", ip+"/32", "via", gw); err != nil {
					d.logger.Warn("failed to add exclusion route", "ip", ip, "via", gw, "error", err)
				} else {
					d.logger.Info("added exclusion route for VPN server", "ip", ip, "via", gw)
				}
			}
		} else {
			d.logger.Warn("could not detect default gateway; VPN server route exclusion skipped")
		}
	}

	// Add routes
	for _, route := range cfg.Routes {
		route = strings.TrimSpace(route)
		if route == "" || route == "0.0.0.0/0" {
			continue // skip default route for safety; user can add it manually
		}
		if err := run("ip", "route", "add", route, "dev", d.name); err != nil {
			d.logger.Warn("failed to add route", "route", route, "error", err)
		} else {
			d.logger.Info("added route", "route", route)
		}
	}

	// Configure DNS via resolvconf if available
	if len(cfg.DNS) > 0 {
		d.configureDNS(cfg.DNS)
	}

	return nil
}

func (d *Device) configureDNS(servers []string) {
	// Try resolvconf first
	resolvconf, err := exec.LookPath("resolvconf")
	if err != nil {
		d.logger.Warn("resolvconf not found; DNS not configured automatically", "dns", servers)
		d.logger.Info("configure DNS manually", "servers", servers)
		return
	}

	input := ""
	for _, s := range servers {
		input += "nameserver " + s + "\n"
	}

	cmd := exec.Command(resolvconf, "-a", d.name, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(input)
	if err := cmd.Run(); err != nil {
		d.logger.Warn("resolvconf failed", "error", err)
		return
	}
	d.logger.Info("DNS configured via resolvconf", "servers", servers)
}

// RemoveDNS removes DNS configuration added by this device.
func (d *Device) RemoveDNS() {
	resolvconf, err := exec.LookPath("resolvconf")
	if err != nil {
		return
	}
	exec.Command(resolvconf, "-d", d.name).Run() //nolint:errcheck
}

// AddDefaultRoute adds a default route through the TUN device,
// preserving the existing default route to the VPN gateway.
func (d *Device) AddDefaultRoute(gatewayIP string) error {
	// Find current default gateway
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return fmt.Errorf("getting default route: %w", err)
	}

	// Add host route to VPN server via current default gateway
	defaultRoute := strings.TrimSpace(string(out))
	if defaultRoute != "" {
		// Extract gateway IP from "default via X.X.X.X dev ethN"
		parts := strings.Fields(defaultRoute)
		for i, p := range parts {
			if p == "via" && i+1 < len(parts) {
				currentGW := parts[i+1]
				// Add route to VPN server through current gateway
				gwIP := net.ParseIP(gatewayIP)
				if gwIP != nil {
					if err := run("ip", "route", "add", gatewayIP+"/32", "via", currentGW); err != nil {
						d.logger.Warn("failed to add host route to VPN server", "error", err)
					}
				}
				break
			}
		}
	}

	// Add default route through TUN
	if err := run("ip", "route", "add", "default", "dev", d.name); err != nil {
		// Try replacing instead
		if err2 := run("ip", "route", "replace", "default", "dev", d.name); err2 != nil {
			return fmt.Errorf("adding default route: %w", err2)
		}
	}

	d.logger.Info("default route set through TUN device")
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// detectDefaultGateway returns the current default gateway IP, or "" if not found.
func detectDefaultGateway() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Parse "default via X.X.X.X dev ethN ..."
	parts := strings.Fields(strings.TrimSpace(string(out)))
	for i, p := range parts {
		if p == "via" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
