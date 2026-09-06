package tui

// HelpText documents operator keybindings shown in the TUI help overlay.
// Honest scope: live decoy event feed + operator actions against the in-process
// intel/SOAR/PCAP packages — not a live mesh topology or eBPF map viewer.
const HelpText = `SHINKIRO TUI — OPERATOR KEYBINDINGS

Navigation
  ↑/k  j/↓     Move selection in the active list
  Tab          Toggle Events ↔ Campaigns pane
  r            Refresh high-score events / campaigns from intel store

Operator actions (selected row)
  b            SOAR block_ip for selected IP — dry-run by default
               (live firewall apply only when tui/up started with --apply
               or SHINKIRO_SOAR_APPLY=1 — same guards as the event pipeline)
  p            On-demand PCAP for selected IP/event (internal/pcap)
  s            Run adversary simulate suite against local mesh host
  c            Generate AWS canary token (HMAC honeytoken)

UI
  ? / h        Toggle this help overlay
  esc / x      Clear status line / close help
  q / Ctrl+C   Quit TUI (stops decoy listeners)

Honesty notes
  • Event list shows live probes + high-score refresh from intel JSONL/correlator
  • block_ip dry-run prints nftables/iptables text; it does not claim silent XDP drops
  • PCAP is forensic libpcap frames, not continuous socket mirroring
  • No live eBPF loader / cluster mesh map in this dashboard`

// KeyHintFooter is the compact footer when help is hidden.
const KeyHintFooter = "?/h help  ↑↓ select  Tab pane  b block  p pcap  s simulate  c canary  r refresh  x clear  q quit"
