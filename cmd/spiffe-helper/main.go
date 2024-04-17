package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	config "github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	exitWhenReady := flag.Bool("exitWhenReady", false, "Exit once the requested objects are retrieved")
	flag.Parse()

	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q\n", *configFile)

	if err := startSidecar(*configFile, *exitWhenReady, log); err != nil {
		log.WithError(err).Error("Exiting due this error")
		os.Exit(1)
	}

	log.Infof("Exiting")
}

func startSidecar(configPath string, exitWhenReady bool, log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	hclConfig, err := config.ParseConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configPath, err)
	}
	if err := config.ValidateConfig(hclConfig, exitWhenReady, log); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	sidecarConfig := config.NewSidecarConfig(hclConfig, log)
	spiffeSidecar := sidecar.New(sidecarConfig)

	return spiffeSidecar.RunDaemon(ctx)
}
