package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	hclconfig "github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
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

	config, err := hclconfig.ParseConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configPath, err)
	}
	if err := hclconfig.ValidateConfig(config, exitWhenReady, log); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	sidecarConfig := &sidecar.Config{
		AddIntermediatesToBundle: config.AddIntermediatesToBundle,
		AgentAddress:             config.AgentAddress,
		Cmd:                      config.Cmd,
		CmdArgs:                  config.CmdArgs,
		CertDir:                  config.CertDir,
		ExitWhenReady:            config.ExitWhenReady,
		JWTBundleFilename:        config.JWTBundleFilename,
		Log:                      log,
		RenewSignal:              config.RenewSignal,
		SvidFileName:             config.SvidFileName,
		SvidKeyFileName:          config.SvidKeyFileName,
		SvidBundleFileName:       config.SvidBundleFileName,
	}

	for _, jwtSvid := range config.JwtSvids {
		sidecarConfig.JwtSvids = append(sidecarConfig.JwtSvids, sidecar.JwtConfig{
			JWTAudience:     jwtSvid.JWTAudience,
			JWTSvidFilename: jwtSvid.JWTSvidFilename,
		})
	}

	spiffeSidecar := sidecar.New(sidecarConfig)
	return spiffeSidecar.RunDaemon(ctx)
}
