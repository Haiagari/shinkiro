package geoip

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/oschwald/geoip2-golang"
)

type mockReader struct {
	dbType  string
	city    *geoip2.City
	country *geoip2.Country
	asn     *geoip2.ASN
	cityErr error
	ctryErr error
	asnErr  error
	closed  bool
}

func (m *mockReader) City(ip net.IP) (*geoip2.City, error) {
	if m.cityErr != nil {
		return nil, m.cityErr
	}
	return m.city, nil
}

func (m *mockReader) Country(ip net.IP) (*geoip2.Country, error) {
	if m.ctryErr != nil {
		return nil, m.ctryErr
	}
	return m.country, nil
}

func (m *mockReader) ASN(ip net.IP) (*geoip2.ASN, error) {
	if m.asnErr != nil {
		return nil, m.asnErr
	}
	return m.asn, nil
}

func (m *mockReader) Metadata() DatabaseMeta {
	return DatabaseMeta{DatabaseType: m.dbType}
}

func (m *mockReader) Close() error {
	m.closed = true
	return nil
}

func TestNewResolver_DisabledWhenPathEmpty(t *testing.T) {
	var logs []string
	var mu sync.Mutex
	r := NewResolver("", WithLogger(func(msg string) {
		mu.Lock()
		logs = append(logs, msg)
		mu.Unlock()
	}))
	if r.Enabled() {
		t.Fatal("expected disabled resolver when path empty")
	}
	rec := r.Lookup("8.8.8.8")
	if !rec.Empty() {
		t.Fatalf("expected empty record when disabled, got %+v", rec)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 || logs[0] != disabledMsg {
		t.Fatalf("expected one %q log, got %#v", disabledMsg, logs)
	}
}

func TestNewResolver_DisabledWhenMissingFile(t *testing.T) {
	var logs []string
	r := NewResolver("/nonexistent/GeoLite2-City.mmdb", WithLogger(func(msg string) {
		logs = append(logs, msg)
	}))
	if r.Enabled() {
		t.Fatal("expected disabled when file missing")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], disabledMsg) {
		t.Fatalf("expected disabled log, got %#v", logs)
	}
}

func TestResolver_LookupCityDB(t *testing.T) {
	city := &geoip2.City{}
	city.Country.IsoCode = "DE"
	city.City.Names = map[string]string{"en": "Frankfurt"}

	r := NewResolver("", WithReader(&mockReader{
		dbType: "GeoLite2-City",
		city:   city,
	}), WithLogger(func(string) {}))

	if !r.Enabled() {
		t.Fatal("expected enabled with injected reader")
	}
	rec := r.Lookup("1.2.3.4")
	if rec.Country != "DE" || rec.City != "Frankfurt" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.ASN != "" {
		t.Fatalf("City DB must not invent ASN, got %q", rec.ASN)
	}
}

func TestResolver_LookupCountryDB(t *testing.T) {
	country := &geoip2.Country{}
	country.Country.IsoCode = "JP"

	r := NewResolver("", WithReader(&mockReader{
		dbType:  "GeoLite2-Country",
		country: country,
	}), WithLogger(func(string) {}))

	rec := r.Lookup("203.0.113.10")
	if rec.Country != "JP" {
		t.Fatalf("expected JP, got %+v", rec)
	}
	if rec.City != "" {
		t.Fatalf("Country DB must not invent city, got %q", rec.City)
	}
}

func TestResolver_LookupASNDB(t *testing.T) {
	asn := &geoip2.ASN{
		AutonomousSystemNumber:       15169,
		AutonomousSystemOrganization: "Google LLC",
	}
	r := NewResolver("", WithReader(&mockReader{
		dbType: "GeoLite2-ASN",
		asn:    asn,
	}), WithLogger(func(string) {}))

	rec := r.Lookup("8.8.8.8")
	if rec.ASN != "AS15169" || rec.Org != "Google LLC" {
		t.Fatalf("unexpected ASN record: %+v", rec)
	}
	if rec.Country != "" || rec.City != "" {
		t.Fatalf("ASN DB must not invent geo, got %+v", rec)
	}
}

func TestResolver_PrivateIP(t *testing.T) {
	r := NewResolver("", WithReader(&mockReader{
		dbType: "GeoLite2-City",
		city:   &geoip2.City{},
	}), WithLogger(func(string) {}))

	rec := r.Lookup("192.168.1.50")
	if rec.Country != "LOCAL" {
		t.Fatalf("expected LOCAL for private IP, got %+v", rec)
	}
}

func TestResolver_InvalidIP(t *testing.T) {
	r := NewResolver("", WithReader(&mockReader{dbType: "GeoLite2-City"}), WithLogger(func(string) {}))
	rec := r.Lookup("not-an-ip")
	if !rec.Empty() {
		t.Fatalf("expected empty for invalid IP, got %+v", rec)
	}
}

func TestEnrichMetadata(t *testing.T) {
	meta := EnrichMetadata(nil, Record{Country: "US", ASN: "AS15169"})
	if meta["geo_country"] != "US" || meta["geo_asn"] != "AS15169" {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
	meta = EnrichMetadata(map[string]string{"geo_country": "US"}, Record{})
	if meta["geo_country"] != "US" {
		t.Fatalf("empty record should not clear geo_country")
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv(EnvPath, "/from/env.mmdb")
	if got := ResolvePath(""); got != "/from/env.mmdb" {
		t.Fatalf("expected env path, got %q", got)
	}
	if got := ResolvePath(" /flag.mmdb "); got != "/flag.mmdb" {
		t.Fatalf("flag should win, got %q", got)
	}
}

func TestResolver_Close(t *testing.T) {
	mock := &mockReader{dbType: "GeoLite2-City"}
	r := NewResolver("", WithReader(mock), WithLogger(func(string) {}))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !mock.closed {
		t.Fatal("expected reader Close")
	}
	if r.Enabled() {
		t.Fatal("expected disabled after Close")
	}
}
