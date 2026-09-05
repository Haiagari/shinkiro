package decoys

import (
	"context"
	"net"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// Decoy defines the unified contract for in-memory protocol honeypot emulators.
type Decoy interface {
	Name() string
	DefaultPort() int
	Protocol() string
	HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error
}
