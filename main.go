package main

import (
	"flag"
	"fmt"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	config, err := ParseConfig(*configFile)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration file: %v\n%v", *configFile, err))
	}
	log("Sidecar is up! Will use agent at %s\n\n", config.AgentAddress)
	if config.Cmd == "" {
		log("Warning: no cmd defined to execute.\n")
	}
	log("Using configuration file: %v\n", *configFile)

	sidecar := NewSidecar(config)

	err = sidecar.RunDaemon()
	if err != nil {
		panic(err)
	}
}
