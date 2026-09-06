package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestBus_StageOrdering(t *testing.T) {
	bus := NewBus()
	var mu sync.Mutex
	var seen []Stage

	record := func(s Stage) Handler {
		return func(ctx context.Context, ev *intel.Event) error {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, s)
			if ev.Metadata == nil {
				ev.Metadata = map[string]string{}
			}
			ev.Metadata[string(s)] = "ok"
			return nil
		}
	}

	bus.On(StageScore, record(StageScore))
	bus.On(StageCorrelate, record(StageCorrelate))
	bus.On(StagePlaybook, record(StagePlaybook))
	bus.On(StageSink, record(StageSink))

	ev := intel.Event{
		ID:          "evt-1",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
		RemoteIP:    "192.0.2.10",
		ThreatScore: 90,
		Action:      "LOGIN",
	}
	res := bus.Process(context.Background(), ev)

	want := []Stage{StageScore, StageCorrelate, StagePlaybook, StageSink}
	if len(seen) != len(want) {
		t.Fatalf("handler invocations: got %v want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %v want %v", i, seen, want)
		}
		if res.StagesRun[i] != want[i] {
			t.Fatalf("StagesRun mismatch at %d: got %v", i, res.StagesRun)
		}
	}
	for _, s := range want {
		if res.Event.Metadata[string(s)] != "ok" {
			t.Errorf("metadata missing for stage %s: %#v", s, res.Event.Metadata)
		}
	}
}

func TestBus_StopsOnHandlerError(t *testing.T) {
	bus := NewBus()
	var ranSink bool

	bus.On(StageScore, func(ctx context.Context, ev *intel.Event) error {
		return nil
	})
	bus.On(StageCorrelate, func(ctx context.Context, ev *intel.Event) error {
		return context.Canceled
	})
	bus.On(StagePlaybook, func(ctx context.Context, ev *intel.Event) error {
		t.Fatal("playbook must not run after correlate error")
		return nil
	})
	bus.On(StageSink, func(ctx context.Context, ev *intel.Event) error {
		ranSink = true
		return nil
	})

	res := bus.Process(context.Background(), intel.Event{RemoteIP: "192.0.2.1"})
	if ranSink {
		t.Fatal("sink ran despite correlate error")
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected error recorded")
	}
	if len(res.StagesRun) != 2 {
		t.Fatalf("expected stages through correlate only, got %v", res.StagesRun)
	}
}

func TestStages_FixedOrder(t *testing.T) {
	got := Stages()
	want := []Stage{StageScore, StageCorrelate, StagePlaybook, StageSink}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
