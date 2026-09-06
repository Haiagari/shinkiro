// Package geoip provides optional MaxMind GeoLite2 enrichment for attacker IPs.
//
// When SHINKIRO_GEOLITE2_PATH / --geoip-db is unset or the .mmdb file is missing,
// enrichment is a no-op (product works without MaxMind). Never invents coordinates
// or heuristic country codes from IP octets.
package geoip

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

const (
	// EnvPath is the environment variable for a local GeoLite2/GeoIP2 .mmdb path.
	EnvPath = "SHINKIRO_GEOLITE2_PATH"

	disabledMsg = "GeoIP disabled"
)

// Record holds geolocation and autonomous system data from a MaxMind lookup.
// Empty fields mean unknown / not present in the configured database — never fabricated.
type Record struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
}

// Empty reports whether the record has no enrichment fields.
func (r Record) Empty() bool {
	return r.Country == "" && r.City == "" && r.ASN == "" && r.Org == ""
}

// Reader abstracts MaxMind City/Country/ASN lookups for unit tests.
// Implementations must not invent coordinates or country codes.
type Reader interface {
	City(ip net.IP) (*geoip2.City, error)
	Country(ip net.IP) (*geoip2.Country, error)
	ASN(ip net.IP) (*geoip2.ASN, error)
	Metadata() DatabaseMeta
	Close() error
}

// DatabaseMeta is the subset of MaxMind metadata we need.
type DatabaseMeta struct {
	DatabaseType string
}

// maxmindReader adapts *geoip2.Reader to Reader.
type maxmindReader struct {
	r *geoip2.Reader
}

func (m *maxmindReader) City(ip net.IP) (*geoip2.City, error)       { return m.r.City(ip) }
func (m *maxmindReader) Country(ip net.IP) (*geoip2.Country, error) { return m.r.Country(ip) }
func (m *maxmindReader) ASN(ip net.IP) (*geoip2.ASN, error)         { return m.r.ASN(ip) }
func (m *maxmindReader) Metadata() DatabaseMeta {
	md := m.r.Metadata()
	return DatabaseMeta{DatabaseType: md.DatabaseType}
}
func (m *maxmindReader) Close() error { return m.r.Close() }

// Resolver looks up IP geolocation using an optional MaxMind database.
type Resolver struct {
	reader  Reader
	dbType  string
	enabled bool

	logOnce sync.Once
	logf    func(string)
}

// Option configures Resolver construction.
type Option func(*Resolver)

// WithLogger sets the one-shot status logger (defaults to discarding).
func WithLogger(logf func(string)) Option {
	return func(r *Resolver) {
		if logf != nil {
			r.logf = logf
		}
	}
}

// WithReader injects a Reader (for tests). Enables the resolver when non-nil.
func WithReader(reader Reader) Option {
	return func(r *Resolver) {
		r.reader = reader
		if reader != nil {
			r.enabled = true
			r.dbType = reader.Metadata().DatabaseType
		}
	}
}

// PathFromEnv returns SHINKIRO_GEOLITE2_PATH (trimmed), or empty if unset.
func PathFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvPath))
}

// ResolvePath prefers explicit flag/path over the environment variable.
func ResolvePath(flagOrPath string) string {
	if p := strings.TrimSpace(flagOrPath); p != "" {
		return p
	}
	return PathFromEnv()
}

// NewResolver builds a resolver from an optional .mmdb path.
// Empty/missing path → disabled no-op enrichment (logs "GeoIP disabled" once).
// Open errors also disable enrichment (product continues without GeoIP).
func NewResolver(path string, opts ...Option) *Resolver {
	r := &Resolver{
		logf: func(string) {},
	}
	for _, o := range opts {
		o(r)
	}

	// Test injection: WithReader already set enabled.
	if r.reader != nil {
		r.logOnce.Do(func() {
			r.logf(fmt.Sprintf("GeoIP enabled (%s)", r.dbTypeOrUnknown()))
		})
		return r
	}

	path = strings.TrimSpace(path)
	if path == "" {
		r.logDisabled()
		return r
	}

	if _, err := os.Stat(path); err != nil {
		r.logOnce.Do(func() {
			r.logf(fmt.Sprintf("%s (path unset or missing: %s)", disabledMsg, path))
		})
		return r
	}

	db, err := geoip2.Open(path)
	if err != nil {
		r.logOnce.Do(func() {
			r.logf(fmt.Sprintf("%s (failed to open %s: %v)", disabledMsg, path, err))
		})
		return r
	}

	adapter := &maxmindReader{r: db}
	r.reader = adapter
	r.dbType = adapter.Metadata().DatabaseType
	r.enabled = true
	r.logOnce.Do(func() {
		r.logf(fmt.Sprintf("GeoIP enabled (MaxMind %s from %s)", r.dbTypeOrUnknown(), path))
	})
	return r
}

func (r *Resolver) logDisabled() {
	r.logOnce.Do(func() {
		r.logf(disabledMsg)
	})
}

func (r *Resolver) dbTypeOrUnknown() string {
	if r.dbType == "" {
		return "unknown"
	}
	return r.dbType
}

// Enabled reports whether a MaxMind database is loaded.
func (r *Resolver) Enabled() bool {
	return r != nil && r.enabled && r.reader != nil
}

// DatabaseType returns the MaxMind database type string, or empty when disabled.
func (r *Resolver) DatabaseType() string {
	if r == nil {
		return ""
	}
	return r.dbType
}

// Close releases the underlying MaxMind reader (no-op when disabled).
func (r *Resolver) Close() error {
	if r == nil || r.reader == nil {
		return nil
	}
	err := r.reader.Close()
	r.reader = nil
	r.enabled = false
	return err
}

// Lookup resolves IP to geolocation / ASN fields from the configured database.
// Private and loopback addresses are tagged Country=LOCAL without inventing ASN/city.
// When disabled or lookup misses, returns an empty Record (no fabricated coords/countries).
func (r *Resolver) Lookup(ipStr string) Record {
	if r == nil || !r.Enabled() {
		return Record{}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Record{}
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return Record{Country: "LOCAL", City: "Private Network", Org: "RFC1918/loopback"}
	}

	return r.lookupPublic(ip)
}

func (r *Resolver) lookupPublic(ip net.IP) Record {
	rec := Record{}
	dbType := strings.ToLower(r.dbType)

	switch {
	case strings.Contains(dbType, "city"):
		city, err := r.reader.City(ip)
		if err == nil && city != nil {
			rec.Country = city.Country.IsoCode
			if name, ok := city.City.Names["en"]; ok {
				rec.City = name
			}
		}
	case strings.Contains(dbType, "country"):
		country, err := r.reader.Country(ip)
		if err == nil && country != nil {
			rec.Country = country.Country.IsoCode
		}
	case strings.Contains(dbType, "asn"):
		asn, err := r.reader.ASN(ip)
		if err == nil && asn != nil {
			if asn.AutonomousSystemNumber > 0 {
				rec.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
			rec.Org = asn.AutonomousSystemOrganization
		}
	case strings.Contains(dbType, "isp"):
		if city, err := r.reader.City(ip); err == nil && city != nil {
			rec.Country = city.Country.IsoCode
			if name, ok := city.City.Names["en"]; ok {
				rec.City = name
			}
		}
		if asn, err := r.reader.ASN(ip); err == nil && asn != nil {
			if asn.AutonomousSystemNumber > 0 {
				rec.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
			rec.Org = asn.AutonomousSystemOrganization
		}
	default:
		if city, err := r.reader.City(ip); err == nil && city != nil {
			rec.Country = city.Country.IsoCode
			if name, ok := city.City.Names["en"]; ok {
				rec.City = name
			}
		} else if country, err := r.reader.Country(ip); err == nil && country != nil {
			rec.Country = country.Country.IsoCode
		}
		if asn, err := r.reader.ASN(ip); err == nil && asn != nil {
			if asn.AutonomousSystemNumber > 0 {
				rec.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
			if rec.Org == "" {
				rec.Org = asn.AutonomousSystemOrganization
			}
		}
	}

	return rec
}

// EnrichMetadata writes geo_* keys into metadata when Lookup returns data.
// Existing keys are overwritten only when the corresponding field is non-empty.
func EnrichMetadata(meta map[string]string, rec Record) map[string]string {
	if meta == nil {
		meta = make(map[string]string)
	}
	if rec.Country != "" {
		meta["geo_country"] = rec.Country
	}
	if rec.City != "" {
		meta["geo_city"] = rec.City
	}
	if rec.ASN != "" {
		meta["geo_asn"] = rec.ASN
	}
	if rec.Org != "" {
		meta["geo_org"] = rec.Org
	}
	return meta
}
