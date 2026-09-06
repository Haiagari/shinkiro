package intel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// EnvThreatFoxAPIKey is the Auth-Key header for ThreatFox (abuse.ch).
	EnvThreatFoxAPIKey = "THREATFOX_API_KEY"
	// EnvAbuseIPDBAPIKey is the Key header for AbuseIPDB.
	EnvAbuseIPDBAPIKey = "ABUSEIPDB_API_KEY"

	defaultThreatFoxURL  = "https://threatfox-api.abuse.ch/api/v1/"
	defaultAbuseIPDBURL  = "https://api.abuseipdb.com/api/v2"
	defaultHTTPTimeout   = 20 * time.Second
)

// ErrMissingAPIKey is returned when a required feed API key env var is unset.
type ErrMissingAPIKey struct {
	EnvVar string
	Feed   string
}

func (e ErrMissingAPIKey) Error() string {
	return fmt.Sprintf("%s: missing API key - set env %s (see docs / README)", e.Feed, e.EnvVar)
}

// ThreatFoxClient queries the ThreatFox community API (POST JSON + Auth-Key header).
type ThreatFoxClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewThreatFoxClient builds a client. API key defaults to THREATFOX_API_KEY.
func NewThreatFoxClient(apiKey string, httpClient *http.Client) *ThreatFoxClient {
	if apiKey == "" {
		apiKey = os.Getenv(EnvThreatFoxAPIKey)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &ThreatFoxClient{
		BaseURL:    defaultThreatFoxURL,
		APIKey:     strings.TrimSpace(apiKey),
		HTTPClient: httpClient,
	}
}

// ThreatFoxIOC is a single IOC record from ThreatFox search/recent responses.
type ThreatFoxIOC struct {
	ID               json.Number `json:"id"`
	IOC              string      `json:"ioc"`
	ThreatType       string      `json:"threat_type"`
	IOCType          string      `json:"ioc_type"`
	Malware          string      `json:"malware"`
	MalwarePrintable string      `json:"malware_printable"`
	Confidence       int         `json:"confidence_level"`
	FirstSeen        string      `json:"first_seen"`
	LastSeen         string      `json:"last_seen"`
	Reporter         string      `json:"reporter"`
	Tags             []string    `json:"tags"`
	Reference        string      `json:"reference"`
}

// ThreatFoxResponse is the top-level ThreatFox API envelope.
type ThreatFoxResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

// SearchIOC looks up an indicator via query=search_ioc.
func (c *ThreatFoxClient) SearchIOC(searchTerm string) ([]ThreatFoxIOC, error) {
	if c.APIKey == "" {
		return nil, ErrMissingAPIKey{EnvVar: EnvThreatFoxAPIKey, Feed: "ThreatFox"}
	}
	body := map[string]any{
		"query":       "search_ioc",
		"search_term": searchTerm,
	}
	return c.postIOCs(body)
}

// RecentIOCs fetches IOCs from the last N days via query=get_iocs (days clamped 1-7).
func (c *ThreatFoxClient) RecentIOCs(days int) ([]ThreatFoxIOC, error) {
	if c.APIKey == "" {
		return nil, ErrMissingAPIKey{EnvVar: EnvThreatFoxAPIKey, Feed: "ThreatFox"}
	}
	if days < 1 {
		days = 1
	}
	if days > 7 {
		days = 7
	}
	body := map[string]any{
		"query": "get_iocs",
		"days":  days,
	}
	return c.postIOCs(body)
}

func (c *ThreatFoxClient) postIOCs(payload map[string]any) ([]ThreatFoxIOC, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	base := c.BaseURL
	if base == "" {
		base = defaultThreatFoxURL
	}
	req, err := http.NewRequest(http.MethodPost, base, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ThreatFox request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ThreatFox HTTP %d: %s", resp.StatusCode, truncateBytes(respBody, 200))
	}

	var envelope ThreatFoxResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("ThreatFox decode: %w", err)
	}
	status := strings.ToLower(envelope.QueryStatus)
	if status != "" && status != "ok" && status != "no_result" {
		return nil, fmt.Errorf("ThreatFox query_status=%q", envelope.QueryStatus)
	}
	if status == "no_result" || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return []ThreatFoxIOC{}, nil
	}

	var list []ThreatFoxIOC
	if err := json.Unmarshal(envelope.Data, &list); err != nil {
		var one ThreatFoxIOC
		if err2 := json.Unmarshal(envelope.Data, &one); err2 != nil {
			return nil, fmt.Errorf("ThreatFox data decode: %w", err)
		}
		if one.IOC != "" {
			list = []ThreatFoxIOC{one}
		}
	}
	return list, nil
}

// AbuseIPDBClient queries AbuseIPDB check API (GET + Key header).
type AbuseIPDBClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewAbuseIPDBClient builds a client. API key defaults to ABUSEIPDB_API_KEY.
func NewAbuseIPDBClient(apiKey string, httpClient *http.Client) *AbuseIPDBClient {
	if apiKey == "" {
		apiKey = os.Getenv(EnvAbuseIPDBAPIKey)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &AbuseIPDBClient{
		BaseURL:    defaultAbuseIPDBURL,
		APIKey:     strings.TrimSpace(apiKey),
		HTTPClient: httpClient,
	}
}

// AbuseIPDBCheckData is the data object from /check.
type AbuseIPDBCheckData struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
}

// AbuseIPDBCheckResponse is the AbuseIPDB /check envelope.
type AbuseIPDBCheckResponse struct {
	Data AbuseIPDBCheckData `json:"data"`
}

// CheckIP looks up an IP reputation (maxAgeInDays default 90).
func (c *AbuseIPDBClient) CheckIP(ip string, maxAgeInDays int) (*AbuseIPDBCheckData, error) {
	if c.APIKey == "" {
		return nil, ErrMissingAPIKey{EnvVar: EnvAbuseIPDBAPIKey, Feed: "AbuseIPDB"}
	}
	if strings.TrimSpace(ip) == "" {
		return nil, fmt.Errorf("AbuseIPDB: ip address required")
	}
	if maxAgeInDays <= 0 {
		maxAgeInDays = 90
	}
	base := c.BaseURL
	if base == "" {
		base = defaultAbuseIPDBURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + "/check")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", strconv.Itoa(maxAgeInDays))
	q.Set("verbose", "")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AbuseIPDB HTTP %d: %s", resp.StatusCode, truncateBytes(respBody, 200))
	}

	var envelope AbuseIPDBCheckResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("AbuseIPDB decode: %w", err)
	}
	return &envelope.Data, nil
}

func truncateBytes(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
