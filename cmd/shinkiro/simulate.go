package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/Haiagari/shinkiro/internal/adversary"
)

func runSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "Target host running Shinkiro mesh")
	_ = fs.Parse(args)

	fmt.Println("⚔️  Launching synthetic adversary attack suite against " + *host)
	sim := adversary.NewSimulator(*host, 2*time.Second)
	scenarios := adversary.DefaultScenarios()

	for i, sc := range scenarios {
		fmt.Printf("[%d/%d] 🎯 Testing %s (%s/%d)... ", i+1, len(scenarios), sc.Name, sc.Protocol, sc.Port)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := sim.RunScenario(ctx, sc)
		cancel()
		if err != nil {
			fmt.Println("⚠️  Failed/Closed: " + err.Error())
		} else {
			fmt.Println("✅ Intercepted & Baited!")
		}
	}
	fmt.Println("✨ Adversarial simulation complete.")
}
