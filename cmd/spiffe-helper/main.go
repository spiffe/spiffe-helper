package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	disableDaemonMode := flag.Bool("disable_daemon_mode", false, "Exit once the requested objects are retrieved")
	flag.Parse()

	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q", *configFile)

	if err := startSidecar(*configFile, *disableDaemonMode, log); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func startSidecar(configFile string, disableDaemonMode bool, log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	hclConfig, err := config.ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("Failed to parse %q: %w", configFile, err)
	}

	if err := config.ValidateConfig(hclConfig, disableDaemonMode, log); err != nil {
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
