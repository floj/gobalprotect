package tun

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"github.com/songgao/water"
	"golang.org/x/sys/unix"
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

// ifaceIndex returns the kernel interface index for this device.
func (d *Device) ifaceIndex() (uint32, error) {
	iface, err := net.InterfaceByName(d.name)
	if err != nil {
		return 0, fmt.Errorf("looking up interface %s: %w", d.name, err)
	}
	return uint32(iface.Index), nil
}

func (d *Device) configure(cfg Config) error {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1400
	}

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing rtnetlink: %w", err)
	}
	defer conn.Close()

	ifIndex, err := d.ifaceIndex()
	if err != nil {
		return err
	}

	// Set IP address (point-to-point: address/32 peer address)
	addr := net.ParseIP(cfg.Address).To4()
	if addr == nil {
		return fmt.Errorf("invalid IP address: %s", cfg.Address)
	}

	if err := conn.Address.New(&rtnetlink.AddressMessage{
		Family:       unix.AF_INET,
		PrefixLength: 32,
		Scope:        unix.RT_SCOPE_UNIVERSE,
		Index:        ifIndex,
		Attributes: &rtnetlink.AddressAttributes{
			Address: addr,
			Local:   addr,
		},
	}); err != nil {
		return fmt.Errorf("setting IP address: %w", err)
	}

	// Set MTU and bring up interface
	mtuU32 := uint32(mtu)
	if err := conn.Link.Set(&rtnetlink.LinkMessage{
		Index:  ifIndex,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			MTU: mtuU32,
		},
	}); err != nil {
		return fmt.Errorf("setting MTU and bringing up interface: %w", err)
	}

	d.logger.Info("TUN device configured", "address", cfg.Address, "mtu", mtu)

	// Add host routes for excluded IPs (e.g. VPN server) via existing default gateway
	if len(cfg.ExcludeIPs) > 0 {
		gw4, _ := detectDefaultGateway(conn, unix.AF_INET)
		gw6, gw6Iface := detectDefaultGateway(conn, unix.AF_INET6)
		for _, ip := range cfg.ExcludeIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			dst := net.ParseIP(ip)
			if dst == nil {
				d.logger.Warn("invalid exclude IP, skipping", "ip", ip)
				continue
			}
			if dst4 := dst.To4(); dst4 != nil {
				if gw4 == nil {
					d.logger.Warn("no IPv4 default gateway; skipping exclude IP", "ip", ip)
					continue
				}
				if err := addRoute(conn, unix.AF_INET, dst4, 32, unix.RT_SCOPE_UNIVERSE, rtnetlink.RouteAttributes{Dst: dst4, Gateway: gw4}); err != nil {
					d.logger.Warn("failed to add exclusion route", "ip", ip, "via", gw4, "error", err)
				} else {
					d.logger.Info("added exclusion route for VPN server", "ip", ip, "via", gw4)
				}
			} else {
				dst = dst.To16()
				if gw6 == nil {
					d.logger.Warn("no IPv6 default gateway; skipping exclude IP", "ip", ip)
					continue
				}
				if err := addRoute(conn, unix.AF_INET6, dst, 128, unix.RT_SCOPE_UNIVERSE, rtnetlink.RouteAttributes{Dst: dst, Gateway: gw6, OutIface: gw6Iface}); err != nil {
					d.logger.Warn("failed to add exclusion route", "ip", ip, "via", gw6, "error", err)
				} else {
					d.logger.Info("added exclusion route for VPN server", "ip", ip, "via", gw6)
				}
			}
		}
	}

	// Add routes
	for _, route := range cfg.Routes {
		route = strings.TrimSpace(route)
		if route == "" || route == "0.0.0.0/0" || route == "::/0" {
			continue
		}
		var dst net.IP
		var prefixLen uint8
		var family uint8
		_, cidr, err := net.ParseCIDR(route)
		if err != nil {
			ip := net.ParseIP(route)
			if ip == nil {
				d.logger.Warn("invalid route, skipping", "route", route, "error", err)
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				dst = ip4
				prefixLen = 32
				family = unix.AF_INET
			} else {
				dst = ip.To16()
				prefixLen = 128
				family = unix.AF_INET6
			}
		} else {
			ones, _ := cidr.Mask.Size()
			prefixLen = uint8(ones)
			if ip4 := cidr.IP.To4(); ip4 != nil {
				dst = ip4
				family = unix.AF_INET
			} else {
				dst = cidr.IP.To16()
				family = unix.AF_INET6
			}
		}
		if err := addRoute(conn, family, dst, prefixLen, unix.RT_SCOPE_LINK, rtnetlink.RouteAttributes{Dst: dst, OutIface: ifIndex}); err != nil {
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

	var input strings.Builder
	for _, s := range servers {
		input.WriteString("nameserver " + s + "\n")
	}

	cmd := exec.Command(resolvconf, "-a", d.name, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(input.String())
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
	exec.Command(resolvconf, "-d", d.name).Run()
}

// AddDefaultRoute adds a default route through the TUN device,
// preserving the existing default route to the VPN gateway.
func (d *Device) AddDefaultRoute(gatewayIP string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dialing rtnetlink: %w", err)
	}
	defer conn.Close()

	ifIndex, err := d.ifaceIndex()
	if err != nil {
		return err
	}

	// Find current default gateway and add host route to VPN server through it
	if gw, _ := detectDefaultGateway(conn, unix.AF_INET); gw != nil {
		serverIP := net.ParseIP(gatewayIP).To4()
		if serverIP != nil {
			if err := addRoute(conn, unix.AF_INET, serverIP, 32, unix.RT_SCOPE_UNIVERSE, rtnetlink.RouteAttributes{Dst: serverIP, Gateway: gw}); err != nil {
				d.logger.Warn("failed to add host route to VPN server", "error", err)
			}
		}
	}

	// Add default route through TUN
	defaultRoute := &rtnetlink.RouteMessage{
		Family:    unix.AF_INET,
		DstLength: 0,
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_STATIC,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Type:      unix.RTN_UNICAST,
		Attributes: rtnetlink.RouteAttributes{
			OutIface: ifIndex,
		},
	}
	if err := conn.Route.Add(defaultRoute); err != nil {
		// Try replacing instead
		if err2 := conn.Route.Replace(defaultRoute); err2 != nil {
			return fmt.Errorf("adding default route: %w", err2)
		}
	}

	d.logger.Info("default route set through TUN device")
	return nil
}

// addRoute adds a route with the given destination prefix, scope, and attributes.
// If the route already exists, it tries to replace it.
func addRoute(conn *rtnetlink.Conn, family uint8, dst net.IP, prefixLen uint8, scope uint8, attrs rtnetlink.RouteAttributes) error {
	msg := &rtnetlink.RouteMessage{
		Family:     family,
		DstLength:  prefixLen,
		Table:      unix.RT_TABLE_MAIN,
		Protocol:   unix.RTPROT_STATIC,
		Scope:      scope,
		Type:       unix.RTN_UNICAST,
		Attributes: attrs,
	}
	if err := conn.Route.Add(msg); err != nil {
		if err2 := conn.Route.Replace(msg); err2 != nil {
			return err2
		}
	}
	return nil
}

// detectDefaultGateway returns the current default gateway IP and outgoing
// interface index for the given address family (unix.AF_INET or unix.AF_INET6),
// or nil/0 if not found.
func detectDefaultGateway(conn *rtnetlink.Conn, family uint8) (net.IP, uint32) {
	routes, err := conn.Route.List()
	if err != nil {
		return nil, 0
	}
	for _, r := range routes {
		if r.Family != family {
			continue
		}
		// Default route: DstLength == 0 and has a gateway
		if r.DstLength == 0 && r.Attributes.Gateway != nil {
			return r.Attributes.Gateway, r.Attributes.OutIface
		}
	}
	return nil, 0
}
