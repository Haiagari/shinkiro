package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// MetricsTracker records aggregate runtime honeypot counters
type MetricsTracker struct {
	TotalConnections uint64
	ProbesBlocked    uint64
	CriticalThreats  uint64
	SSHAttempts      uint64
	RedisAttempts    uint64
	DockerAttempts   uint64
	DatabaseAttempts uint64
}

var DefaultTracker = &MetricsTracker{}

func IncConnections()  { atomic.AddUint64(&DefaultTracker.TotalConnections, 1) }
func IncBlocked()      { atomic.AddUint64(&DefaultTracker.ProbesBlocked, 1) }
func IncCritical()     { atomic.AddUint64(&DefaultTracker.CriticalThreats, 1) }
func IncSSH()          { atomic.AddUint64(&DefaultTracker.SSHAttempts, 1) }
func IncRedis()        { atomic.AddUint64(&DefaultTracker.RedisAttempts, 1) }
func IncDocker()       { atomic.AddUint64(&DefaultTracker.DockerAttempts, 1) }
func IncDatabase()     { atomic.AddUint64(&DefaultTracker.DatabaseAttempts, 1) }

// Handler renders Prometheus/OpenMetrics formatted plain text
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP shinkiro_connections_total Total incoming connection probes\n")
	fmt.Fprintf(w, "# TYPE shinkiro_connections_total counter\n")
	fmt.Fprintf(w, "shinkiro_connections_total %d\n", atomic.LoadUint64(&DefaultTracker.TotalConnections))

	fmt.Fprintf(w, "# HELP shinkiro_probes_blocked_total Total attacker IPs mitigated by defense engine\n")
	fmt.Fprintf(w, "# TYPE shinkiro_probes_blocked_total counter\n")
	fmt.Fprintf(w, "shinkiro_probes_blocked_total %d\n", atomic.LoadUint64(&DefaultTracker.ProbesBlocked))

	fmt.Fprintf(w, "# HELP shinkiro_critical_threats_total Total critical severity exploits observed\n")
	fmt.Fprintf(w, "# TYPE shinkiro_critical_threats_total counter\n")
	fmt.Fprintf(w, "shinkiro_critical_threats_total %d\n", atomic.LoadUint64(&DefaultTracker.CriticalThreats))

	fmt.Fprintf(w, "# HELP shinkiro_decoy_probes Total probes categorized by decoy service\n")
	fmt.Fprintf(w, "# TYPE shinkiro_decoy_probes counter\n")
	fmt.Fprintf(w, "shinkiro_decoy_probes{service=\"ssh\"} %d\n", atomic.LoadUint64(&DefaultTracker.SSHAttempts))
	fmt.Fprintf(w, "shinkiro_decoy_probes{service=\"redis\"} %d\n", atomic.LoadUint64(&DefaultTracker.RedisAttempts))
	fmt.Fprintf(w, "shinkiro_decoy_probes{service=\"docker\"} %d\n", atomic.LoadUint64(&DefaultTracker.DockerAttempts))
	fmt.Fprintf(w, "shinkiro_decoy_probes{service=\"database\"} %d\n", atomic.LoadUint64(&DefaultTracker.DatabaseAttempts))
}
