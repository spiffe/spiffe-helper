package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/health"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	daemonModeFlag := flag.Bool(config.DaemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()
	log := logrus.WithField("system", "spiffe-helper")

	if err := startSidecar(*configFile, *daemonModeFlag, log); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	if err := health.StartHealthServer(*configFile, *daemonModeFlag, log, spiffeSidecar); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper health check server")
		os.Exit(1)
	}

	log.Infof("Exiting")
	os.Exit(0)
}

var spiffeSidecar *sidecar.Sidecar

func startSidecar(configFile string, daemonModeFlag bool, log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hclConfig, err := config.ParseConfigFile(log, configFile, daemonModeFlag)
	if err != nil {
		return err
	}

	if err := hclConfig.ValidateConfig(log); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	sidecarConfig := config.NewSidecarConfig(hclConfig, log)
	spiffeSidecar = sidecar.New(sidecarConfig)

	if !*hclConfig.DaemonMode {
		log.Info("Daemon mode disabled")
		return spiffeSidecar.Run(ctx)
	}

	log.Info("Launching daemon")
	return spiffeSidecar.RunDaemon(ctx)
}
