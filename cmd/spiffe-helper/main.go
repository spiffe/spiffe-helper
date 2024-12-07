package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
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

	if err := startSidecar(*configFile, *daemonModeFlag, log); err != nil {
		log.WithError(err).Errorf("Error starting spiffe-helper")
		os.Exit(1)
	}

	if err := startHealthServer(*configFile, *daemonModeFlag, log); err != nil {
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

	log.Infof("Using configuration file: %q", configFile)
	hclConfig, err := config.ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configFile, err)
	}
	hclConfig.ParseConfigFlagOverrides(daemonModeFlag, daemonModeFlagName)

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

func startHealthServer(configFile string, daemonModeFlag bool, log logrus.FieldLogger) error {
	hclConfig, err := config.ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configFile, err)
	}
	hclConfig.ParseConfigFlagOverrides(daemonModeFlag, daemonModeFlagName)
	if err := hclConfig.ValidateConfig(log); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if *hclConfig.DaemonMode && *hclConfig.EnableHealthCheck {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			healthy := spiffeSidecar.CheckHealth()
			if healthy {
				_, err := w.Write([]byte(http.StatusText(http.StatusOK)))
				log.Error(err)
				if err != nil {
					return
				}
			} else {
				statusText := http.StatusText(http.StatusServiceUnavailable)
				b, err := json.Marshal(spiffeSidecar.GetFileWritesSuccess())
				if err != nil {
					statusText = string(b)
				}
				http.Error(w, statusText, http.StatusServiceUnavailable)
			}
		})
		server := &http.Server{
			Addr:              ":" + strconv.Itoa(hclConfig.HealthCheckPort),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
		}
		log.Fatal(server.ListenAndServe())
	}
	return nil
}
