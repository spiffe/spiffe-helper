package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/health"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

const (
	daemonModeFlagName = "daemon-mode"
)

func main() {
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	daemonModeFlag := flag.Bool(daemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()
	log := logrus.WithField("system", "spiffe-helper")

	log.Infof("Using configuration file: %q", *configFile)
	hclConfig, err := config.ParseConfig(*configFile, *daemonModeFlag, daemonModeFlagName)
	if err != nil {
		log.WithError(err).Errorf("failed to parse configuration")
		os.Exit(1)
	}

	if err := hclConfig.ValidateConfig(log); err != nil {
		log.WithError(err).Errorf("invalid configuration")
		os.Exit(1)
	}

	spiffeSidecar, err := startSidecar(hclConfig, log)
	if err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	if *hclConfig.DaemonMode && hclConfig.HealthCheck.ListenerEnabled {
		if err := health.StartHealthServer(hclConfig.HealthCheck, log, spiffeSidecar); err != nil {
			log.WithError(err).Errorf("Error starting spiffe-helper health check server")
			os.Exit(1)
		}
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func startSidecar(hclConfig *config.Config, log logrus.FieldLogger) (*sidecar.Sidecar, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sidecarConfig := config.NewSidecarConfig(hclConfig, log)
	spiffeSidecar := sidecar.New(sidecarConfig)

	if !*hclConfig.DaemonMode {
		log.Info("Daemon mode disabled")
		return spiffeSidecar, spiffeSidecar.Run(ctx)
	}

	log.Info("Launching daemon")
	return spiffeSidecar, spiffeSidecar.RunDaemon(ctx)
}
