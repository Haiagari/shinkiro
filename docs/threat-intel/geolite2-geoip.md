# Optional MaxMind GeoLite2 GeoIP Enrichment

Shinkiro can enrich attacker events with **country / city / ASN** fields from a local MaxMind `.mmdb` database. GeoIP is **optional**: the product runs fully without it.

Docs hub: [`../README.md`](../README.md). CLI: [`../cli-reference.md`](../cli-reference.md)#shinkiro-geoip.

---

## Honesty

| Claim | Reality |
| :--- | :--- |
| GeoIP always on | **No** — disabled when path unset/missing; logs `GeoIP disabled` once |
| Demo / heuristic prefixes | **Removed** — no invented country codes from IP octets |
| Invented coordinates | **Never** — latitude/longitude are not fabricated or written |
| License key in repo | **Never** — download DBs with your own MaxMind account |

---

## Enable

1. Create a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup) and generate a **license key**.
2. Download a GeoLite2 database (City recommended; Country or ASN also work):
   - Web: [GeoLite2 free geolocation data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
   - Or `geoipupdate` with your account ID + license key (see MaxMind docs)
3. Point Shinkiro at the `.mmdb` file:

```bash
export SHINKIRO_GEOLITE2_PATH=/var/lib/GeoIP/GeoLite2-City.mmdb
./bin/shinkiro up

./bin/shinkiro up --geoip-db /var/lib/GeoIP/GeoLite2-City.mmdb
./bin/shinkiro tui --geoip-db /var/lib/GeoIP/GeoLite2-City.mmdb
```

---

## Ops test CLI

```bash
./bin/shinkiro geoip --ip 1.2.3.4
./bin/shinkiro geoip --ip 1.2.3.4 --geoip-db /var/lib/GeoIP/GeoLite2-City.mmdb
./bin/shinkiro geoip --ip 8.8.8.8 --format json
```

---

## Pipeline wiring

The Score stage in `shinkiro up` / `tui` calls `internal/intel/geoip.Resolver.Lookup` and writes non-empty fields into event metadata:

- `geo_country` — ISO country code (or `LOCAL` for private/loopback)
- `geo_city` — English city name when present (City DB)
- `geo_asn` — `ASnnnnn` when present (ASN DB)
- `geo_org` — ASN organization / local tag

Empty fields are omitted (not filled with fake values).

---

## Database types

| `.mmdb` type | Fields filled |
| :--- | :--- |
| GeoLite2-City / GeoIP2-City | country, city |
| GeoLite2-Country / GeoIP2-Country | country |
| GeoLite2-ASN | asn, org |

Only **one** database path is configured at a time (`SHINKIRO_GEOLITE2_PATH` / `--geoip-db`).

## Dependency

Uses `github.com/oschwald/geoip2-golang` v1.13 (Go 1.24–compatible crypto pin in `go.mod`). Do **not** commit MaxMind `.mmdb` binaries or license keys to the repository (`*.mmdb` is gitignored).
