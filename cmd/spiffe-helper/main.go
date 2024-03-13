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
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	//damonMode := flag.Bool("daemon_mode", true, "Exit once the requested objects are retrieved")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q", *configFile)

	if err := runHelper(ctx, *configFile, log); err != nil {
		log.WithError(err).Errorf("Error running spiffe-helper")
		os.Exit(1)
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func runHelper(ctx context.Context, configFile string, log logrus.FieldLogger) error {
	config, err := ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("Failed to parse %q: %w", configFile, err)
		os.Exit(1)
	}

	x509Enabled, jwtBundleEnabled, jwtSVIDsEnabled, err := ValidateConfig(config, log)
	if err != nil {
		return fmt.Errorf("Invalid configuration: %w", err)
		os.Exit(1)
	}

	sidecarConfig := &sidecar.Config{
		AgentAddress:             config.AgentAddress,
		Cmd:                      config.Cmd,
		CmdArgs:                  config.CmdArgs,
		CertDir:                  config.CertDir,
		SVIDFileName:             config.SVIDFileName,
		SVIDKeyFileName:          config.SVIDKeyFileName,
		SVIDBundleFileName:       config.SVIDBundleFileName,
		Log:                      log,
		RenewSignal:              config.RenewSignal,
		AddIntermediatesToBundle: config.AddIntermediatesToBundle,
		JWTBundleFilename:        config.JWTBundleFilename,
		X509Enabled:              x509Enabled,
		JWTBundleEnabled:         jwtBundleEnabled,
		JWTSVIDsEnabled:          jwtSVIDsEnabled,
	}

	for _, jwtSVID := range config.JWTSVIDs {
		sidecarConfig.JWTSVIDs = append(sidecarConfig.JWTSVIDs, sidecar.JWTConfig{
			JWTAudience:     jwtSVID.JWTAudience,
			JWTSVIDFilename: jwtSVID.JWTSVIDFilename,
		})
	}

	spiffeSidecar := sidecar.New(sidecarConfig)

	if !*config.DaemonMode {
		log.Info("Daemon mode disabled")
		return spiffeSidecar.Run(ctx)
	} else {
		log.Info("Launching daemon")
		return spiffeSidecar.RunDaemon(ctx)
	}
}
