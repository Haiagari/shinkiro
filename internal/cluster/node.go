package cluster

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

const (
	// DefaultMaxBodyBytes caps JSON bodies on join/ingest (1 MiB).
	DefaultMaxBodyBytes = 1 << 20

	// EnvClusterToken is the shared secret for hub join & ingest.
	// Empty value = lab-only insecure mode (auth disabled).
	EnvClusterToken = "SHINKIRO_CLUSTER_TOKEN"

	// HeaderClusterToken is an alternate header for the shared secret
	// (Authorization: Bearer <token> is also accepted).
	HeaderClusterToken = "X-Shinkiro-Cluster-Token"
)

// Node is a sensor registered with the central HTTP hub (hub-and-spoke).
// Nodes are not gossip peers and do not form an encrypted mesh.
type Node struct {
	ID       string    `json:"id"`
	Address  string    `json:"address"`
	LastSeen time.Time `json:"last_seen"`
	Active   bool      `json:"active"`
}

// HubConfig controls HTTP hardening for the cluster hub.
// Token empty => lab-only insecure mode (no auth). Prefer setting
// SHINKIRO_CLUSTER_TOKEN (or Config.Token) for any non-lab deployment.
// TLS is optional: set both TLSCertFile and TLSKeyFile, or terminate TLS
// at a reverse proxy in front of plain HTTP.
type HubConfig struct {
	Token        string
	TLSCertFile  string
	TLSKeyFile   string
	MaxBodyBytes int64
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DefaultHubConfig loads token from SHINKIRO_CLUSTER_TOKEN and sensible timeouts.
func DefaultHubConfig() HubConfig {
	return HubConfig{
		Token:        strings.TrimSpace(os.Getenv(EnvClusterToken)),
		MaxBodyBytes: DefaultMaxBodyBytes,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Hub is a hub-and-spoke HTTP aggregator for remote Shinkiro sensors.
// It is deliberately not UDP gossip, not a kernel/eBPF mesh, and not peer discovery.
type Hub struct {
	nodes  map[string]*Node
	events chan intel.Event
	mu     sync.RWMutex
	server *http.Server
	cfg    HubConfig
}

// NewHub builds a hub using DefaultHubConfig (env token + default limits).
func NewHub(events chan intel.Event) *Hub {
	return NewHubWithConfig(events, DefaultHubConfig())
}

// NewHubWithConfig builds a hub with explicit hardening settings.
func NewHubWithConfig(events chan intel.Event, cfg HubConfig) *Hub {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 15 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	cfg.Token = strings.TrimSpace(cfg.Token)
	return &Hub{
		nodes:  make(map[string]*Node),
		events: events,
		cfg:    cfg,
	}
}

// TokenConfigured reports whether shared-secret auth is enforced.
func (h *Hub) TokenConfigured() bool {
	return h.cfg.Token != ""
}

// Config returns a copy of the hub hardening config.
func (h *Hub) Config() HubConfig {
	return h.cfg
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// extractToken reads Authorization: Bearer or X-Shinkiro-Cluster-Token.
func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if len(auth) >= len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
			return strings.TrimSpace(auth[len(prefix):])
		}
	}
	return strings.TrimSpace(r.Header.Get(HeaderClusterToken))
}

// RequireToken wraps handlers with shared-secret checks.
// Empty hub token = lab-only insecure mode (request allowed).
// Non-empty token: missing or wrong secret => 401 JSON error.
func (h *Hub) RequireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.cfg.Token == "" {
			next(w, r)
			return
		}
		got := extractToken(r)
		if got == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "missing cluster token")
			return
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.Token)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "invalid cluster token")
			return
		}
		next(w, r)
	}
}

// RegisterNode adds or refreshes a remote sensor registration.
func (h *Hub) RegisterNode(id, address string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nodes[id] = &Node{
		ID:       id,
		Address:  address,
		LastSeen: time.Now().UTC(),
		Active:   true,
	}
}

type joinRequest struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

// JoinHandler registers a remote sensor with the hub (HTTP join, not gossip membership).
func (h *Hub) JoinHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	var req joinRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "invalid join payload")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Address = strings.TrimSpace(req.Address)
	if req.ID == "" || req.Address == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "id and address are required")
		return
	}

	h.RegisterNode(req.ID, req.Address)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "joined",
		"id":      req.ID,
		"address": req.Address,
		"model":   "hub-and-spoke-http",
	})
}

// IngestHandler accepts JSON intel.Event bodies from remote sensors.
func (h *Hub) IngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	var ev intel.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "invalid event JSON")
		return
	}
	if strings.TrimSpace(ev.ID) == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "event id is required")
		return
	}

	select {
	case h.events <- ev:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ingested"})
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "buffer_full", "hub event buffer full")
	}
}

// NodesHandler returns the registered node map.
func (h *Hub) NodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]Node, len(h.nodes))
	for k, v := range h.nodes {
		out[k] = *v
	}
	writeJSON(w, http.StatusOK, out)
}

// HealthHandler is liveness (unauthenticated).
func (h *Hub) HealthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ReadyHandler is readiness (unauthenticated) and reports auth/TLS mode honestly.
func (h *Hub) ReadyHandler(w http.ResponseWriter, r *http.Request) {
	authMode := "insecure-lab"
	if h.TokenConfigured() {
		authMode = "token"
	}
	tlsEnabled := h.cfg.TLSCertFile != "" && h.cfg.TLSKeyFile != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ready",
		"auth_mode": authMode,
		"tls":       tlsEnabled,
		"model":     "hub-and-spoke-http",
	})
}

// Handler returns the mux with health/ready public and join/ingest/nodes protected.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.HealthHandler)
	mux.HandleFunc("/readyz", h.ReadyHandler)
	mux.HandleFunc("/api/v1/cluster/join", h.RequireToken(h.JoinHandler))
	mux.HandleFunc("/api/v1/cluster/ingest", h.RequireToken(h.IngestHandler))
	mux.HandleFunc("/api/v1/cluster/nodes", h.RequireToken(h.NodesHandler))
	return mux
}

// StartHTTP serves the hub on :port. Uses ListenAndServeTLS when both cert and key are set.
func (h *Hub) StartHTTP(ctx context.Context, port int) error {
	h.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        h.Handler(),
		ReadTimeout:    h.cfg.ReadTimeout,
		WriteTimeout:   h.cfg.WriteTimeout,
		IdleTimeout:    h.cfg.IdleTimeout,
		MaxHeaderBytes: 1 << 14,
	}

	go func() {
		<-ctx.Done()
		if h.server == nil {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.server.Shutdown(shutdownCtx)
	}()

	hasCert := h.cfg.TLSCertFile != ""
	hasKey := h.cfg.TLSKeyFile != ""
	switch {
	case hasCert && hasKey:
		return h.server.ListenAndServeTLS(h.cfg.TLSCertFile, h.cfg.TLSKeyFile)
	case hasCert || hasKey:
		return fmt.Errorf("cluster hub TLS requires both --tls-cert and --tls-key (or leave both empty and terminate TLS upstream)")
	default:
		return h.server.ListenAndServe()
	}
}
