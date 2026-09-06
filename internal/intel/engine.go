package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Engine struct {
	eventsPath string
	mu         sync.Mutex
	blocklist  map[string]int // IP -> cumulative threat score
	Correlator *Correlator
}

func NewEngine(eventsPath string) (*Engine, error) {
	if eventsPath == "" {
		eventsPath = "data/events.jsonl"
	}

	dir := filepath.Dir(eventsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create intel events dir: %w", err)
	}

	return &Engine{
		eventsPath: eventsPath,
		blocklist:  make(map[string]int),
		Correlator: NewCorrelator(2 * time.Hour),
	}, nil
}
