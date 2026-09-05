package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// Node represents a distributed Shinkiro mesh sensor node
type Node struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	LastSeen  time.Time `json:"last_seen"`
	Active    bool      `json:"active"`
}

// Hub manages multi-node mesh synchronization of threat intelligence
type Hub struct {
	nodes   map[string]*Node
	events  chan intel.Event
	mu      sync.RWMutex
	server  *http.Server
}

func NewHub(events chan intel.Event) *Hub {
	return &Hub{
		nodes:  make(map[string]*Node),
		events: events,
	}
}

// RegisterNode adds or updates a remote sensor node
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

// IngestHandler provides an HTTP ingestion endpoint for remote Shinkiro sensors
func (h *Hub) IngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ev intel.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	select {
	case h.events <- ev:
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"ingested"}`))
	default:
		http.Error(w, "hub buffer full", http.StatusServiceUnavailable)
	}
}

// StartHTTP starts the cluster synchronization endpoint
func (h *Hub) StartHTTP(ctx context.Context, port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/ingest", h.IngestHandler)
	mux.HandleFunc("/api/v1/cluster/nodes", func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.nodes)
	})

	h.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		if h.server != nil {
			_ = h.server.Close()
		}
	}()

	return h.server.ListenAndServe()
}
