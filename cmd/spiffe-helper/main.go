package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	log := logger.Std
	log.Infof("Using configuration file: %q\n", *configFile)
	config, err := ParseConfig(*configFile)
	if err != nil {
		log.Errorf("Failed to parse %q: %v", *configFile, err)
		os.Exit(1)
	}

	if err := ValidateConfig(config); err != nil {
		log.Errorf("Invalid configuration: %v", err)
		os.Exit(1)
	}
	config.Log = log

	// TODO: add default agent socket path
	log.Infof("Connecting to agent at %q\n", config.AgentAddress)
	if config.Cmd == "" {
		log.Warnf("No cmd defined to execute.")
	}

	if err = runDaemon(config); err != nil {
		log.Errorf("Exiting due to error: %w", err)
		os.Exit(1)
	}

	log.Infof("Exiting")
}

func runDaemon(config *sidecar.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	spiffeSidecar := sidecar.NewSidecar(config)
	return spiffeSidecar.RunDaemon(ctx)
}
