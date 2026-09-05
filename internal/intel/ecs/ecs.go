package ecs

import (
	"encoding/json"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// ECSEvent represents an event normalized according to Elastic Common Schema (ECS) v8.x
type ECSEvent struct {
	Timestamp string           `json:"@timestamp"`
	ECS       ECSVersion       `json:"ecs"`
	Event     EventFields      `json:"event"`
	Source    EndpointFields   `json:"source"`
	Host      HostFields       `json:"host"`
	Service   ServiceFields    `json:"service"`
	User      *UserFields      `json:"user,omitempty"`
	Network   NetworkFields    `json:"network"`
	Threat    ThreatFields     `json:"threat"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type ECSVersion struct {
	Version string `json:"version"`
}

type EventFields struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Category []string `json:"category"`
	Type     []string `json:"type"`
	Outcome  string   `json:"outcome"`
	Action   string   `json:"action"`
	Severity int      `json:"severity"`
	RiskScore float64 `json:"risk_score"`
}

type EndpointFields struct {
	IP   string `json:"ip"`
	Port int    `json:"port,omitempty"`
	Geo  *Geo   `json:"geo,omitempty"`
	AS   *AS    `json:"as,omitempty"`
}

type Geo struct {
	CountryName string `json:"country_name,omitempty"`
	CityName    string `json:"city_name,omitempty"`
}

type AS struct {
	Number       int    `json:"number,omitempty"`
	Organization string `json:"organization_name,omitempty"`
}

type HostFields struct {
	Hostname string `json:"hostname"`
}

type ServiceFields struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type UserFields struct {
	Name string `json:"name,omitempty"`
}

type NetworkFields struct {
	Transport string `json:"transport"`
	Protocol  string `json:"protocol"`
}

type ThreatFields struct {
	Framework string        `json:"framework"`
	Tactic    *TacticFields `json:"tactic,omitempty"`
}

type TacticFields struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Reference string `json:"reference"`
}

// ConvertToECS maps an internal Shinkiro event to ECS format
func ConvertToECS(ev intel.Event, nodeHostname string) ECSEvent {
	if nodeHostname == "" {
		nodeHostname = "shinkiro-sensor"
	}

	ecsEv := ECSEvent{
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339Nano),
		ECS: ECSVersion{
			Version: "8.11.0",
		},
		Event: EventFields{
			ID:        ev.ID,
			Kind:      "alert",
			Category:  []string{"intrusion_detection", "threat"},
			Type:      []string{"indicator", "denied"},
			Outcome:   "success", // Honeynet successfully baited/intercepted
			Action:    ev.Action,
			Severity:  severityToInt(ev.Severity),
			RiskScore: float64(ev.ThreatScore),
		},
		Source: EndpointFields{
			IP:   ev.RemoteIP,
			Port: ev.RemotePort,
		},
		Host: HostFields{
			Hostname: nodeHostname,
		},
		Service: ServiceFields{
			Name: ev.DecoyName,
			Type: "honeypot",
		},
		Network: NetworkFields{
			Transport: "tcp",
			Protocol:  ev.DecoyName,
		},
		Threat: ThreatFields{
			Framework: "MITRE ATT&CK",
			Tactic: &TacticFields{
				ID:        "TA0001",
				Name:      "Initial Access",
				Reference: "https://attack.mitre.org/tactics/TA0001/",
			},
		},
		Labels: ev.Metadata,
	}

	if ev.Username != "" {
		ecsEv.User = &UserFields{
			Name: ev.Username,
		}
	}

	if ev.Metadata != nil {
		country := ev.Metadata["geo_country"]
		city := ev.Metadata["geo_city"]
		if country != "" || city != "" {
			ecsEv.Source.Geo = &Geo{
				CountryName: country,
				CityName:    city,
			}
		}
		asn := ev.Metadata["geo_asn"]
		org := ev.Metadata["geo_org"]
		if asn != "" || org != "" {
			ecsEv.Source.AS = &AS{
				Organization: org,
			}
		}
	}

	return ecsEv
}

func severityToInt(s intel.Severity) int {
	switch s {
	case intel.SeverityCritical:
		return 10
	case intel.SeverityHigh:
		return 8
	case intel.SeverityMedium:
		return 5
	case intel.SeverityLow:
		return 3
	default:
		return 1
	}
}

// ConvertBatchToECSJSON converts multiple events to an ECS JSON array
func ConvertBatchToECSJSON(events []intel.Event, hostname string) ([]byte, error) {
	ecsList := make([]ECSEvent, 0, len(events))
	for _, ev := range events {
		ecsList = append(ecsList, ConvertToECS(ev, hostname))
	}
	return json.MarshalIndent(ecsList, "", "  ")
}
