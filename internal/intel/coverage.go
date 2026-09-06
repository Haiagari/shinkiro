package intel

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// TechniqueRef is a MITRE ATT&CK technique ID with optional display name.
// Only techniques already documented in docs/decoys/decoy-matrix.md or MapToMitre are listed.
type TechniqueRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// DecoyCoverageEntry maps a decoy service to its documented ATT&CK techniques.
type DecoyCoverageEntry struct {
	Decoy      string         `json:"decoy"`
	Port       int            `json:"default_port,omitempty"`
	Techniques []TechniqueRef `json:"techniques"`
	Source     string         `json:"source"` // decoy-matrix | map_to_mitre
}

// CoverageReport summarizes ATT&CK technique coverage across decoys.
type CoverageReport struct {
	Decoys            []DecoyCoverageEntry `json:"decoys"`
	UniqueTechniques  []TechniqueRef       `json:"unique_techniques"`
	TechniqueToDecoys map[string][]string  `json:"technique_to_decoys"`
	TotalDecoys       int                  `json:"total_decoys"`
	TotalTechniques   int                  `json:"total_techniques"`
	Note              string               `json:"note"`
}

// techniqueNames is a small lookup for human-readable names of IDs we actually tag.
var techniqueNames = map[string]string{
	"T1078":     "Valid Accounts",
	"T1078.001": "Valid Accounts: Default Accounts",
	"T1078.004": "Valid Accounts: Cloud Accounts",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.004": "Unix Shell",
	"T1021":     "Remote Services",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1021.004": "SSH",
	"T1110":     "Brute Force",
	"T1190":     "Exploit Public-Facing Application",
	"T1552.001": "Unsecured Credentials: Credentials In Files",
	"T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
	"T1609":     "Container Administration Command",
	"T1496":     "Resource Hijacking",
	"T1613":     "Container and Resource Discovery",
	"T1083":     "File and Directory Discovery",
	"T1566":     "Phishing",
	"T1071.003": "Application Layer Protocol: Mail Protocols",
	"T1071.004": "Application Layer Protocol: DNS",
	"T1568":     "Dynamic Resolution",
	"T1210":     "Exploitation of Remote Services",
	"T1595":     "Active Scanning",
	"T0855":     "Unauthorized Command Message",
	"T0858":     "Detect Operating Mode",
	"T0812":     "Change Operating Mode",
}

// DecoyMatrixCoverage is the ATT&CK mapping from docs/decoys/decoy-matrix.md (not invented).
func DecoyMatrixCoverage() []DecoyCoverageEntry {
	entries := []DecoyCoverageEntry{
		{Decoy: "ssh", Port: 2222, Source: "decoy-matrix", Techniques: refs("T1078", "T1059.004", "T1021.004")},
		{Decoy: "telnet", Port: 2323, Source: "decoy-matrix", Techniques: refs("T1078", "T1059.004")},
		{Decoy: "modbus", Port: 502, Source: "decoy-matrix", Techniques: refs("T0855", "T0858", "T0812")},
		{Decoy: "redis", Port: 6379, Source: "decoy-matrix", Techniques: refs("T1059", "T1190")},
		{Decoy: "docker", Port: 2375, Source: "decoy-matrix", Techniques: refs("T1609", "T1496")},
		{Decoy: "k8s", Port: 6443, Source: "decoy-matrix", Techniques: refs("T1613", "T1078.001")},
		{Decoy: "postgres", Port: 5432, Source: "decoy-matrix", Techniques: refs("T1078.001", "T1110")},
		{Decoy: "mongo", Port: 27017, Source: "decoy-matrix", Techniques: refs("T1078", "T1190")},
		{Decoy: "elastic", Port: 9200, Source: "decoy-matrix", Techniques: refs("T1190", "T1083")},
		{Decoy: "http", Port: 8080, Source: "decoy-matrix", Techniques: refs("T1190", "T1552.001")},
		{Decoy: "aws-imds", Port: 8169, Source: "decoy-matrix", Techniques: refs("T1552.005", "T1078.004")},
		{Decoy: "mqtt", Port: 1883, Source: "decoy-matrix", Techniques: refs("T1078", "T1190")},
		{Decoy: "smb", Port: 4445, Source: "decoy-matrix", Techniques: refs("T1021.002", "T1210")},
		{Decoy: "smtp", Port: 2525, Source: "decoy-matrix", Techniques: refs("T1566", "T1071.003")},
		{Decoy: "dns", Port: 1053, Source: "decoy-matrix", Techniques: refs("T1071.004", "T1568")},
	}
	return entries
}

// RuntimeMapperCoverage lists techniques produced by MapToMitre (event action heuristics).
func RuntimeMapperCoverage() []DecoyCoverageEntry {
	samples := []struct {
		decoy, action, command string
	}{
		{"ssh", "LOGIN", ""},
		{"ssh", "EXEC", "whoami"},
		{"redis", "EVAL", ""},
		{"docker", "GET", ""},
		{"k8s", "GET", ""},
		{"aws-imds", "GET", ""},
		{"http", "PROBE", ""},
	}
	seen := map[string]TechniqueRef{}
	for _, s := range samples {
		m := MapToMitre(s.decoy, s.action, s.command)
		if m.TechniqueID == "" {
			continue
		}
		seen[m.TechniqueID] = TechniqueRef{ID: m.TechniqueID, Name: m.TechniqueName}
	}
	techs := make([]TechniqueRef, 0, len(seen))
	for _, tr := range seen {
		techs = append(techs, tr)
	}
	sort.Slice(techs, func(i, j int) bool { return techs[i].ID < techs[j].ID })
	return []DecoyCoverageEntry{{
		Decoy:      "(runtime MapToMitre)",
		Source:     "map_to_mitre",
		Techniques: techs,
	}}
}

// BuildCoverageReport aggregates decoy-matrix + optional runtime mapper coverage.
func BuildCoverageReport(includeRuntimeMapper bool) CoverageReport {
	decoys := DecoyMatrixCoverage()
	if includeRuntimeMapper {
		decoys = append(decoys, RuntimeMapperCoverage()...)
	}

	techToDecoys := map[string][]string{}
	unique := map[string]TechniqueRef{}
	for _, d := range decoys {
		for _, t := range d.Techniques {
			unique[t.ID] = t
			if !contains(techToDecoys[t.ID], d.Decoy) {
				techToDecoys[t.ID] = append(techToDecoys[t.ID], d.Decoy)
			}
		}
	}

	uniqList := make([]TechniqueRef, 0, len(unique))
	for _, t := range unique {
		uniqList = append(uniqList, t)
	}
	sort.Slice(uniqList, func(i, j int) bool { return uniqList[i].ID < uniqList[j].ID })

	ids := make([]string, 0, len(techToDecoys))
	for id := range techToDecoys {
		ids = append(ids, id)
		sort.Strings(techToDecoys[id])
	}
	sort.Strings(ids)
	orderedMap := map[string][]string{}
	for _, id := range ids {
		orderedMap[id] = techToDecoys[id]
	}

	matrixCount := 0
	for _, d := range decoys {
		if d.Source == "decoy-matrix" {
			matrixCount++
		}
	}

	return CoverageReport{
		Decoys:            decoys,
		UniqueTechniques:  uniqList,
		TechniqueToDecoys: orderedMap,
		TotalDecoys:       matrixCount,
		TotalTechniques:   len(uniqList),
		Note:              "Coverage derived from docs/decoys/decoy-matrix.md and internal/intel.MapToMitre - no invented ATT&CK mappings.",
	}
}

// FormatCoverageTable renders a human-readable coverage summary.
func FormatCoverageTable(r CoverageReport) string {
	var b strings.Builder
	b.WriteString("Shinkiro ATT&CK coverage (documented decoy tags)\n")
	b.WriteString(strings.Repeat("=", 88))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%-12s %-6s %-50s %s\n", "DECOY", "PORT", "TECHNIQUES", "SOURCE"))
	b.WriteString(strings.Repeat("-", 88))
	b.WriteString("\n")
	for _, d := range r.Decoys {
		ids := make([]string, 0, len(d.Techniques))
		for _, t := range d.Techniques {
			ids = append(ids, t.ID)
		}
		port := "-"
		if d.Port > 0 {
			port = fmt.Sprintf("%d", d.Port)
		}
		b.WriteString(fmt.Sprintf("%-12s %-6s %-50s %s\n",
			d.Decoy, port, truncate(strings.Join(ids, ", "), 50), d.Source))
	}
	b.WriteString(strings.Repeat("-", 88))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Unique techniques: %d across %d decoys (matrix)\n", r.TotalTechniques, r.TotalDecoys))
	b.WriteString("\nBy technique -> decoys:\n")
	ids := make([]string, 0, len(r.TechniqueToDecoys))
	for id := range r.TechniqueToDecoys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name := techniqueNames[id]
		if name == "" {
			for _, t := range r.UniqueTechniques {
				if t.ID == id && t.Name != "" {
					name = t.Name
					break
				}
			}
		}
		label := id
		if name != "" {
			label = id + " (" + name + ")"
		}
		b.WriteString(fmt.Sprintf("  %-40s  %s\n", label, strings.Join(r.TechniqueToDecoys[id], ", ")))
	}
	b.WriteString("\n")
	b.WriteString(r.Note)
	b.WriteString("\n")
	return b.String()
}

// CoverageReportJSON returns indented JSON for --format json.
func CoverageReportJSON(r CoverageReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func refs(ids ...string) []TechniqueRef {
	out := make([]TechniqueRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, TechniqueRef{ID: id, Name: techniqueNames[id]})
	}
	return out
}
