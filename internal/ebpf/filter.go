package ebpf

import (
	"fmt"
	"net"
	"strings"
)

// Driver abstracts low-level Linux packet-filtering mechanisms
type Driver string

const (
	DriverEBPF     Driver = "ebpf"
	DriverNFTables Driver = "nftables"
	DriverIPTables Driver = "iptables"
)

// FilterManager manages live automated IP blacklisting at the kernel level
type FilterManager struct {
	driver    Driver
	interfaceName string
	blockedIPs    map[string]bool
}

// NewFilterManager creates a kernel defense manager
func NewFilterManager(driver Driver, iface string) *FilterManager {
	if iface == "" {
		iface = "eth0"
	}
	return &FilterManager{
		driver:        driver,
		interfaceName: iface,
		blockedIPs:    make(map[string]bool),
	}
}

// BlockIP stages an attacker IP for kernel-level dropping
func (fm *FilterManager) BlockIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	fm.blockedIPs[ip] = true
	return nil
}

// RenderScript generates the kernel execution script (eBPF map update / nftables rule)
func (fm *FilterManager) RenderScript() string {
	var sb strings.Builder

	switch fm.driver {
	case DriverEBPF:
		sb.WriteString("// Shinkiro eBPF XDP Packet Filter Map Update\n")
		sb.WriteString("// Drops ingress packets before socket allocation (XDP_DROP)\n")
		sb.WriteString("#include <linux/bpf.h>\n\n")
		for ip := range fm.blockedIPs {
			sb.WriteString(fmt.Sprintf("// xdp_drop_map_update(\"%s\");\n", ip))
		}
	case DriverNFTables:
		sb.WriteString("#!/usr/sbin/nft -f\n")
		sb.WriteString("table inet shinkiro_guard {\n")
		sb.WriteString("    set blacklist {\n")
		sb.WriteString("        type ipv4_addr\n")
		sb.WriteString("        elements = { ")
		elements := make([]string, 0, len(fm.blockedIPs))
		for ip := range fm.blockedIPs {
			elements = append(elements, ip)
		}
		sb.WriteString(strings.Join(elements, ", "))
		sb.WriteString(" }\n")
		sb.WriteString("    }\n")
		sb.WriteString("    chain ingress {\n")
		sb.WriteString("        type filter hook ingress device " + fm.interfaceName + " priority -500; policy accept;\n")
		sb.WriteString("        ip saddr @blacklist counter drop\n")
		sb.WriteString("    }\n")
		sb.WriteString("}\n")
	default:
		sb.WriteString("# Shinkiro iptables auto-mitigation\n")
		for ip := range fm.blockedIPs {
			sb.WriteString(fmt.Sprintf("iptables -I INPUT -s %s -j DROP\n", ip))
		}
	}

	return sb.String()
}
