package main

import (
	"context"
	"flag"
	"fmt"
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

	// TODO: logger will be replaced in a near future
	log := logger.Std
	log.Infof("Using configuration file: %q\n", *configFile)

	if err := startSidecar(*configFile, log); err != nil {
		log.Errorf("Exiting due to error: %w", err)
		os.Exit(1)
	}

	log.Infof("Exiting")
}

func startSidecar(configPath string, log logger.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	spiffeSidecar, err := sidecar.New(configPath, log)
	if err != nil {
		return fmt.Errorf("Failed to create sidecar: %w", err)
	}

	return spiffeSidecar.RunDaemon(ctx)
}
