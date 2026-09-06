package intel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestThreatFoxClient_MissingKey(t *testing.T) {
	c := NewThreatFoxClient("  ", http.DefaultClient)
	c.APIKey = ""
	_, err := c.SearchIOC("1.2.3.4")
	if err == nil {
		t.Fatal("expected missing key error")
	}
	var mk ErrMissingAPIKey
	if !asMissingKey(err, &mk) {
		t.Fatalf("expected ErrMissingAPIKey, got %T %v", err, err)
	}
	if mk.EnvVar != EnvThreatFoxAPIKey {
		t.Fatalf("env var: %s", mk.EnvVar)
	}
}

func TestThreatFoxClient_SearchIOC_httptest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Auth-Key") != "tf-test-key" {
			t.Errorf("Auth-Key header missing/wrong")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["query"] != "search_ioc" {
			t.Errorf("query=%v", body["query"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"query_status": "ok",
			"data": [{
				"id": "42",
				"ioc": "198.51.100.10",
				"threat_type": "botnet_cc",
				"ioc_type": "ip:port",
				"malware": "mirai",
				"malware_printable": "Mirai",
				"confidence_level": 90,
				"first_seen": "2026-09-01 00:00:00 UTC",
				"reporter": "abuse_ch",
				"tags": ["botnet"]
			}]
		}`))
	}))
	defer srv.Close()

	c := NewThreatFoxClient("tf-test-key", srv.Client())
	c.BaseURL = srv.URL
	iocs, err := c.SearchIOC("198.51.100.10")
	if err != nil {
		t.Fatalf("SearchIOC: %v", err)
	}
	if len(iocs) != 1 || iocs[0].IOC != "198.51.100.10" {
		t.Fatalf("unexpected IOCs: %+v", iocs)
	}
	if iocs[0].Confidence != 90 {
		t.Fatalf("confidence=%d", iocs[0].Confidence)
	}
}

func TestThreatFoxClient_RecentIOCs_noResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"query_status":"no_result","data":null}`))
	}))
	defer srv.Close()
	c := NewThreatFoxClient("k", srv.Client())
	c.BaseURL = srv.URL
	iocs, err := c.RecentIOCs(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(iocs) != 0 {
		t.Fatalf("want empty, got %v", iocs)
	}
}

func TestAbuseIPDBClient_MissingKey(t *testing.T) {
	c := NewAbuseIPDBClient("", nil)
	c.APIKey = ""
	_, err := c.CheckIP("8.8.8.8", 90)
	if err == nil {
		t.Fatal("expected missing key")
	}
	if !strings.Contains(err.Error(), EnvAbuseIPDBAPIKey) {
		t.Fatalf("error should mention env: %v", err)
	}
}

func TestAbuseIPDBClient_CheckIP_httptest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Key") != "abuse-key" {
			t.Errorf("Key header wrong")
		}
		if !strings.Contains(r.URL.Path, "/check") {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.URL.Query().Get("ipAddress") != "203.0.113.50" {
			t.Errorf("ipAddress=%s", r.URL.Query().Get("ipAddress"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"ipAddress": "203.0.113.50",
				"isPublic": true,
				"ipVersion": 4,
				"isWhitelisted": false,
				"abuseConfidenceScore": 77,
				"countryCode": "US",
				"usageType": "Data Center/Web Hosting/Transit",
				"isp": "Example ISP",
				"domain": "example.net",
				"hostnames": [],
				"totalReports": 12,
				"numDistinctUsers": 4,
				"lastReportedAt": "2026-09-05T12:00:00+00:00"
			}
		}`))
	}))
	defer srv.Close()

	c := NewAbuseIPDBClient("abuse-key", srv.Client())
	c.BaseURL = srv.URL
	data, err := c.CheckIP("203.0.113.50", 30)
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if data.AbuseConfidenceScore != 77 {
		t.Fatalf("score=%d", data.AbuseConfidenceScore)
	}
	if data.IPAddress != "203.0.113.50" {
		t.Fatalf("ip=%s", data.IPAddress)
	}
}

func asMissingKey(err error, target *ErrMissingAPIKey) bool {
	e, ok := err.(ErrMissingAPIKey)
	if !ok {
		return false
	}
	*target = e
	return true
}
