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

	log := logger.Std
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	log.Infof("Using configuration file: %q\n", *configFile)
	config, err := ParseConfig(*configFile)
	if err != nil {
		log.Errorf("error parsing configuration file: %v\n%v", *configFile, err)
		panic(err)
	}
	config.Log = log

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
