package main

import (
	"flag"
	"context"
	"github.com/apex/log"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	config, err := ParseConfig(*configFile)
	if err != nil {
		log.Fatalf("error parsing configuration file: %v\n%v", *configFile, err)
	}

	log.Infof("Sidecar is up! Will use agent at %s\n\n", config.AgentAddress)
	if config.Cmd == "" {
		log.Warn("Warning: no cmd defined to execute.\n")
	}

	log.Infof("Using configuration file: %v\n", *configFile)

	sidecar, err := NewSidecar(config)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	err = sidecar.RunDaemon(ctx)
	if err != nil {
		panic(err)
	}
}
