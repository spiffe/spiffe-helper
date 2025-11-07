package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/health"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"github.com/spiffe/spiffe-helper/pkg/util"
	"github.com/spiffe/spiffe-helper/pkg/version"
)

const (
	daemonModeFlagName = "daemon-mode"
)

func main() {
	versionFlag := flag.Bool("version", false, "print version")
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	configFormat := flag.String("config-format", "auto", "Configuration format: hcl, json, yaml, or auto (default: auto)")
	daemonModeFlag := flag.Bool(daemonModeFlagName, true, "Toggle running as a daemon to rotate X.509/JWT or just fetch and exit")
	flag.Parse()
	
		if *versionFlag {
			fmt.Println(version.Version())
			os.Exit(0)
		}

	// Set initial log level from environment variable if provided (for early logging)
	// This will be overridden by config value if set
	if logLevelStr := os.Getenv("SPIFFE_HLP_LOG_LEVEL"); logLevelStr != "" {
		if level, err := logrus.ParseLevel(logLevelStr); err == nil {
			logrus.SetLevel(level)
		}
	}

	log := logrus.WithField("system", "spiffe-helper")

	log.Infof("Using configuration file: %q", *configFile)
	log.Infof("Using configuration format: %q", *configFormat)

	configFileToUse := *configFile
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		log.Info("Configuration file not found, configuring via environment variables")
		configFileToUse = ""
	} else if *configFormat == "hcl" {
		// TODO: remove this in 0.11.0
		log.Warn("HCL format is deprecated and will be removed in 0.11.0. Use JSON or YAML instead.")
	}

	helperConfig, err := config.ParseConfig(configFileToUse, *configFormat, *daemonModeFlag, daemonModeFlagName)
	if err != nil {
		log.WithError(err).Errorf("failed to parse configuration")
		os.Exit(1)
	}

	// Set log level from config if provided (overrides env var)
	if helperConfig.LogLevel != "" {
		if level, err := logrus.ParseLevel(helperConfig.LogLevel); err == nil {
			logrus.SetLevel(level)
			log = logrus.WithField("system", "spiffe-helper") // Recreate logger with new level
		} else {
			log.Warnf("Invalid log level in config: %s, ignoring", helperConfig.LogLevel)
		}
	}

	if err := helperConfig.ValidateConfig(log); err != nil {
		log.WithError(err).Errorf("invalid configuration")
		os.Exit(1)
	}

	helperConfig.LogConfig(log)

	if err = startSidecar(helperConfig, log); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func startSidecar(helperConfig *config.Config, log logrus.FieldLogger) error {
	sidecarConfig := config.NewSidecarConfig(helperConfig, log)
	spiffeSidecar := sidecar.New(sidecarConfig)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !*helperConfig.DaemonMode {
		log.Info("Daemon mode disabled")
		return spiffeSidecar.Run(ctx)
	}

	log.Info("Launching daemon")
	tasks := []func(context.Context) error{
		spiffeSidecar.RunDaemon,
	}

	if helperConfig.HealthCheck.ListenerEnabled {
		healthServer := health.New(&helperConfig.HealthCheck, log, spiffeSidecar)
		tasks = append(tasks, healthServer.Start)
	}

	err := util.RunTasks(ctx, tasks...)
	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}
