package intel

import "strings"

// MitreAttack holds MITRE ATT&CK technique and tactic mappings
type MitreAttack struct {
	TacticID     string `json:"tactic_id"`
	TacticName   string `json:"tactic_name"`
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Reference    string `json:"reference"`
}

// MapToMitre maps a Shinkiro event action and decoy to MITRE ATT&CK
func MapToMitre(decoy, action, command string) MitreAttack {
	actUpper := strings.ToUpper(action)
	cmdUpper := strings.ToUpper(command)

	// Credential Access / Brute Force
	if strings.Contains(actUpper, "AUTH") || strings.Contains(actUpper, "LOGIN") || strings.Contains(actUpper, "PASSWORD") {
		return MitreAttack{
			TacticID:      "TA0006",
			TacticName:    "Credential Access",
			TechniqueID:   "T1110",
			TechniqueName: "Brute Force",
			Reference:     "https://attack.mitre.org/techniques/T1110/",
		}
	}

	// Execution / Command and Scripting Interpreter
	if cmdUpper != "" || strings.Contains(actUpper, "EXEC") || strings.Contains(actUpper, "EVAL") || strings.Contains(actUpper, "SHELL") {
		return MitreAttack{
			TacticID:      "TA0002",
			TacticName:    "Execution",
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Reference:     "https://attack.mitre.org/techniques/T1059/",
		}
	}

	// Lateral Movement
	if decoy == "ssh" || decoy == "smb" || decoy == "telnet" {
		return MitreAttack{
			TacticID:      "TA0008",
			TacticName:    "Lateral Movement",
			TechniqueID:   "T1021",
			TechniqueName: "Remote Services",
			Reference:     "https://attack.mitre.org/techniques/T1021/",
		}
	}

	// Cloud / Container Discovery or Exploitation
	if decoy == "docker" || decoy == "k8s" || decoy == "aws" {
		return MitreAttack{
			TacticID:      "TA0001",
			TacticName:    "Initial Access",
			TechniqueID:   "T1190",
			TechniqueName: "Exploit Public-Facing Application",
			Reference:     "https://attack.mitre.org/techniques/T1190/",
		}
	}

	// Default: Reconnaissance / Active Scanning
	return MitreAttack{
		TacticID:      "TA0043",
		TacticName:    "Reconnaissance",
		TechniqueID:   "T1595",
		TechniqueName: "Active Scanning",
		Reference:     "https://attack.mitre.org/techniques/T1595/",
	}
}
