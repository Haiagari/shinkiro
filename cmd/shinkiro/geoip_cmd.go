package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Haiagari/shinkiro/internal/intel/geoip"
)

func runGeoIP(args []string) {
	fs := flag.NewFlagSet("geoip", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address to look up")
	dbPath := fs.String("geoip-db", "", "Path to GeoLite2/GeoIP2 .mmdb (overrides SHINKIRO_GEOLITE2_PATH)")
	format := fs.String("format", "table", "Output format: table | json")
	_ = fs.Parse(args)

	if strings.TrimSpace(*ip) == "" {
		fmt.Fprintln(os.Stderr, "geoip: require --ip <address>")
		fmt.Fprintln(os.Stderr, "Optional: --geoip-db <path> or env SHINKIRO_GEOLITE2_PATH")
		fmt.Fprintln(os.Stderr, "Download GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
		os.Exit(1)
	}

	path := geoip.ResolvePath(*dbPath)
	var status string
	resolver := geoip.NewResolver(path, geoip.WithLogger(func(msg string) {
		status = msg
	}))
	defer func() { _ = resolver.Close() }()

	rec := resolver.Lookup(*ip)

	switch strings.ToLower(*format) {
	case "json":
		out := map[string]any{
			"ip":       *ip,
			"enabled":  resolver.Enabled(),
			"database": resolver.DatabaseType(),
			"db_path":  path,
			"status":   status,
			"country":  rec.Country,
			"city":     rec.City,
			"asn":      rec.ASN,
			"org":      rec.Org,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "geoip: encode: %v\n", err)
			os.Exit(1)
		}
	default:
		if status != "" {
			fmt.Println(status)
		}
		fmt.Printf("IP:       %s\n", *ip)
		fmt.Printf("Enabled:  %v\n", resolver.Enabled())
		if resolver.DatabaseType() != "" {
			fmt.Printf("Database: %s\n", resolver.DatabaseType())
		}
		if path != "" {
			fmt.Printf("Path:     %s\n", path)
		}
		fmt.Printf("Country:  %s\n", emptyDash(rec.Country))
		fmt.Printf("City:     %s\n", emptyDash(rec.City))
		fmt.Printf("ASN:      %s\n", emptyDash(rec.ASN))
		fmt.Printf("Org:      %s\n", emptyDash(rec.Org))
		if !resolver.Enabled() {
			fmt.Println()
			fmt.Println("Hint: set SHINKIRO_GEOLITE2_PATH or --geoip-db to a GeoLite2 City/Country/ASN .mmdb")
			fmt.Println("      Product works without GeoIP; enrichment is optional.")
		}
	}
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
