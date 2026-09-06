// Package pipeline provides an in-process Event → Score → Correlate → Playbook → Sink bus.
// Decoy emit paths feed the bus; stages wire the existing intel, soar, and sink packages.
package pipeline

import (
	"context"
	"fmt"
	"sync"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// Stage identifies an ordered processing step in the event pipeline.
type Stage string

const (
	StageScore     Stage = "score"
	StageCorrelate Stage = "correlate"
	StagePlaybook  Stage = "playbook"
	StageSink      Stage = "sink"
)

// stageOrder is the fixed Event → Score → Correlate → Playbook → Sink sequence.
var stageOrder = []Stage{StageScore, StageCorrelate, StagePlaybook, StageSink}

// Handler processes a mutable event pointer within a stage.
// Returning a non-nil error stops further stages for that event.
type Handler func(ctx context.Context, ev *intel.Event) error

// Result summarizes one Process call for observers and tests.
type Result struct {
	Event           intel.Event
	StagesRun       []Stage
	PlaybookActions []string
	PCAPPath        string
	PCAPTriggered   bool
	Errors          []string
}

// Bus is a small in-process pipeline that existing decoy/emit channels can feed.
type Bus struct {
	mu       sync.Mutex
	handlers map[Stage][]Handler
	onAfter  []func(Result)
}

// NewBus creates an empty pipeline bus. Register handlers per stage before Process.
func NewBus() *Bus {
	return &Bus{
		handlers: map[Stage][]Handler{
			StageScore:     nil,
			StageCorrelate: nil,
			StagePlaybook:  nil,
			StageSink:      nil,
		},
	}
}

// On registers a handler at the given stage. Handlers run in registration order.
func (b *Bus) On(stage Stage, h Handler) {
	if h == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[stage] = append(b.handlers[stage], h)
}

// AfterProcess registers a callback invoked after all stages complete (success or partial).
func (b *Bus) AfterProcess(fn func(Result)) {
	if fn == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onAfter = append(b.onAfter, fn)
}

// Process runs ev through Score → Correlate → Playbook → Sink in order.
func (b *Bus) Process(ctx context.Context, ev intel.Event) Result {
	res := Result{Event: ev, StagesRun: make([]Stage, 0, len(stageOrder))}
	ptr := &ev

	b.mu.Lock()
	handlers := make(map[Stage][]Handler, len(b.handlers))
	for k, v := range b.handlers {
		cp := make([]Handler, len(v))
		copy(cp, v)
		handlers[k] = cp
	}
	after := make([]func(Result), len(b.onAfter))
	copy(after, b.onAfter)
	b.mu.Unlock()

	for _, stage := range stageOrder {
		res.StagesRun = append(res.StagesRun, stage)
		for _, h := range handlers[stage] {
			if err := h(ctx, ptr); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", stage, err))
				res.Event = *ptr
				for _, fn := range after {
					fn(res)
				}
				return res
			}
		}
	}

	res.Event = *ptr
	for _, fn := range after {
		fn(res)
	}
	return res
}

// RunChannel consumes events from ch until it is closed or ctx is cancelled.
func (b *Bus) RunChannel(ctx context.Context, ch <-chan intel.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_ = b.Process(ctx, ev)
		}
	}
}

// Stages returns the fixed pipeline stage order (for tests and docs).
func Stages() []Stage {
	out := make([]Stage, len(stageOrder))
	copy(out, stageOrder)
	return out
}
