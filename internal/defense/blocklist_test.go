package defense

import (
	"strings"
	"testing"
)

func TestGenerateRules(t *testing.T) {
	ips := []string{"198.51.100.1", "203.0.113.55"}

	// 1. iptables
	ipt := GenerateRules(ips, FormatIPTables)
	if !strings.Contains(ipt, "iptables -A INPUT -s 198.51.100.1 -j DROP") {
		t.Errorf("expected iptables rule: %s", ipt)
	}

	// 2. CIDR
	cidr := GenerateRules(ips, FormatCIDR)
	if !strings.Contains(cidr, "198.51.100.1/32") {
		t.Errorf("expected CIDR output: %s", cidr)
	}

	// 3. nftables
	nft := GenerateRules(ips, FormatNFTables)
	if !strings.Contains(nft, "shinkiro_filter") {
		t.Errorf("expected nftables table: %s", nft)
	}
}
