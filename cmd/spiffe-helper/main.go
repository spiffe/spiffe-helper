package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q\n", *configFile)

	if err := startSidecar(*configFile, log); err != nil {
		log.WithError(err).Error("Exiting due this error")
		os.Exit(1)
	}

	log.Infof("Exiting")
}

func startSidecar(configPath string, log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	spiffeSidecar, err := sidecar.New(configPath, log)
	if err != nil {
		return fmt.Errorf("Failed to create sidecar: %w", err)
	}

	return spiffeSidecar.RunDaemon(ctx)
}
