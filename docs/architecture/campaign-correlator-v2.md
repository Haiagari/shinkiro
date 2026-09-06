## Campaign Correlator v2

`internal/intel/correlator.go` groups events with deterministic rules (not ML):

1. Same source IP
2. Sliding session window (default 2h)
3. Ordered decoy hop path (`HopPath`) when the attacker moves between services

Also tracks technique IDs, event/action rolls, and explicit `grouping` reasons (`same_src_ip`, `session_window`, `decoy_hop`).

CLI:

```bash
shinkiro campaigns
shinkiro campaigns --format json --window 2h
```

Rebuilds from `data/events.jsonl` (or `--events`). The TUI Campaigns pane continues to read the live correlator.

See also `docs/architecture/threat-scoring.md` section 3.
