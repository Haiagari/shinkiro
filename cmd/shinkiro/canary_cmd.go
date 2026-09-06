package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/Haiagari/shinkiro/internal/canary"
)

func runCanary(args []string) {
	if len(args) > 0 && args[0] == "generate" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("canary", flag.ExitOnError)
	label := fs.String("label", "canary-prod-seed", "Attribution tag for the canary token")
	_ = fs.Parse(args)

	token := canary.GenerateAWSKey(*label)
	data, _ := json.MarshalIndent(token, "", "  ")
	fmt.Println(string(data))
}
