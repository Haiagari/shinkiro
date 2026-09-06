package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// AgentClient talks to a central hub over HTTP (spoke to hub).
// Use the same SHINKIRO_CLUSTER_TOKEN (or Token field) the hub expects.
type AgentClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func (c *AgentClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *AgentClient) setAuth(req *http.Request) {
	token := strings.TrimSpace(c.Token)
	if token == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
}

// Join registers this sensor with the hub.
func (c *AgentClient) Join(ctx context.Context, id, address string) error {
	body, err := json.Marshal(joinRequest{ID: id, Address: address})
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/api/v1/cluster/join"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	slurp, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("cluster join: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(slurp)))
	}
	return nil
}

// Ingest posts a single intel.Event to the hub.
func (c *AgentClient) Ingest(ctx context.Context, ev intel.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/api/v1/cluster/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	slurp, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("cluster ingest: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(slurp)))
	}
	return nil
}
