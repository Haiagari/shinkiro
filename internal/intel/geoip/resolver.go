package geoip

import (
	"fmt"
	"net"
	"strings"
)

// Record holds geolocation and autonomous system data
type Record struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
}

// Resolver simulates or resolves IP geolocation without network latency
type Resolver struct {
	customRange map[string]Record
}

func NewResolver() *Resolver {
	r := &Resolver{
		customRange: make(map[string]Record),
	}

	// Pre-seed known cloud and scan networks for offline speed
	r.customRange["198.51.100."] = Record{Country: "US", City: "Ashburn", ASN: "AS14618", Org: "Amazon.com, Inc."}
	r.customRange["203.0.113."] = Record{Country: "DE", City: "Frankfurt", ASN: "AS24940", Org: "Hetzner Online GmbH"}
	r.customRange["192.0.2."] = Record{Country: "NL", City: "Amsterdam", ASN: "AS16509", Org: "Amazon Data Services"}

	return r
}

// Lookup resolves IP to geolocation and ASN
func (r *Resolver) Lookup(ipStr string) Record {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Record{Country: "UNKNOWN", City: "UNKNOWN", ASN: "AS0", Org: "Invalid IP"}
	}

	if ip.IsPrivate() || ip.IsLoopback() {
		return Record{Country: "LOCAL", City: "Private Network", ASN: "AS0", Org: "RFC1918 Private"}
	}

	for prefix, rec := range r.customRange {
		if strings.HasPrefix(ipStr, prefix) {
			return rec
		}
	}

	// Deterministic fallback for demonstration based on IP octets
	octets := strings.Split(ipStr, ".")
	if len(octets) == 4 {
		switch octets[0] {
		case "45", "185", "194":
			return Record{Country: "RU", City: "Moscow", ASN: "AS48282", Org: "Hostkey B.V."}
		case "103", "116", "118":
			return Record{Country: "SG", City: "Singapore", ASN: "AS13335", Org: "Cloudflare, Inc."}
		case "51", "162", "192":
			return Record{Country: "FR", City: "Paris", ASN: "AS16276", Org: "OVH SAS"}
		default:
			return Record{Country: "US", City: "North Bergen", ASN: "AS396982", Org: "Google LLC"}
		}
	}

	return Record{Country: fmt.Sprintf("CC-%s", octets[0]), City: "Cloud Node", ASN: "AS15169", Org: "Autonomous System"}
}
