package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	log := logrus.WithField("system", "spiffe-helper")

	if err := startSidecar(log); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func startSidecar(log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	configFile, daemonModeFlag := config.ParseFlags()
	log.Infof("Using configuration file: %q", configFile)

	hclConfig, err := config.ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configFile, err)
	}

	if err := config.ValidateConfig(hclConfig, daemonModeFlag, log); err != nil {
		return fmt.Errorf("Invalid configuration: %w", err)
	}

	sidecarConfig := config.NewSidecarConfig(hclConfig, log)
	spiffeSidecar := sidecar.New(sidecarConfig)

	if !*hclConfig.DaemonMode {
		log.Info("Daemon mode disabled")
		return spiffeSidecar.Run(ctx)
	}

	log.Info("Launching daemon")
	return spiffeSidecar.RunDaemon(ctx)
}
