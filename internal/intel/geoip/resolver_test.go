package geoip

import (
	"testing"
)

func TestResolver_Lookup(t *testing.T) {
	r := NewResolver()

	// 1. Private RFC1918
	rec := r.Lookup("192.168.1.50")
	if rec.Country != "LOCAL" {
		t.Errorf("expected LOCAL for private IP, got %s", rec.Country)
	}

	// 2. Pre-seeded custom range
	recUS := r.Lookup("198.51.100.42")
	if recUS.Country != "US" || recUS.ASN != "AS14618" {
		t.Errorf("expected US / AS14618, got %s / %s", recUS.Country, recUS.ASN)
	}

	// 3. Fallback deterministic lookup
	recSG := r.Lookup("103.21.244.10")
	if recSG.Country != "SG" {
		t.Errorf("expected SG for 103.x, got %s", recSG.Country)
	}
}
