package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/decoys"
	"github.com/Haiagari/shinkiro/internal/intel"
)

// Multiplexer coordinates concurrent protocol listeners and routes incoming traffic.
type Multiplexer struct {
	cfg       *config.Config
	decoys    map[string]decoys.Decoy
	events    chan intel.Event
	listeners []net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup
	running   bool
}

// NewMultiplexer creates a new listener engine.
func NewMultiplexer(cfg *config.Config, events chan intel.Event) *Multiplexer {
	return &Multiplexer{
		cfg:    cfg,
		decoys: make(map[string]decoys.Decoy),
		events: events,
	}
}

// RegisterDecoy binds a protocol decoy implementation.
func (m *Multiplexer) RegisterDecoy(d decoys.Decoy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decoys[d.Name()] = d
}

// Start spawns listeners for all enabled decoys.
func (m *Multiplexer) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("multiplexer already running")
	}
	m.running = true
	m.mu.Unlock()

	for name, svcCfg := range m.cfg.Services {
		if !svcCfg.Enabled {
			continue
		}

		decoy, exists := m.decoys[name]
		if !exists {
			continue
		}

		port := svcCfg.Port
		if port == 0 {
			port = decoy.DefaultPort()
		}

		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			m.Stop()
			return fmt.Errorf("failed to listen on %s (%s): %w", addr, name, err)
		}

		m.mu.Lock()
		m.listeners = append(m.listeners, ln)
		m.mu.Unlock()

		m.wg.Add(1)
		go m.serve(ctx, ln, decoy)
	}

	return nil
}

func (m *Multiplexer) serve(ctx context.Context, ln net.Listener, decoy decoys.Decoy) {
	defer m.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// Listener was closed
				return
			}
		}

		m.wg.Add(1)
		go func(c net.Conn) {
			defer m.wg.Done()
			defer c.Close()

			if m.cfg.IdleTimeout > 0 {
				_ = c.SetDeadline(time.Now().Add(m.cfg.IdleTimeout))
			}

			_ = decoy.HandleConnection(ctx, c, m.events)
		}(conn)
	}
}

// Stop closes all listeners and waits for active connections to finish.
func (m *Multiplexer) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false

	for _, ln := range m.listeners {
		if ln != nil {
			_ = ln.Close()
		}
	}
	m.listeners = nil
	m.mu.Unlock()

	m.wg.Wait()
}
