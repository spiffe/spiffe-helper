package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/pkg/disk"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	//damonMode := flag.Bool("daemon_mode", true, "Exit once the requested objects are retrieved")
	flag.Parse()

	ctx := context.Background()
	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q\n", *configFile)

	config, err := ParseConfig(*configFile)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse \"%q\"", *configFile)
		os.Exit(1)
	}

	x509Enabled, err := ValidateConfig(config, log)
	if err != nil {
		log.WithError(err).Errorf("Invalid configuration")
		os.Exit(1)
	}

	if !*config.DaemonMode {
		if x509Enabled {
			fetchX509Context(ctx, config)
		}
	} else {
		if err := startSidecar(config, log); err != nil {
			log.WithError(err).Error("Exiting due this error")
			os.Exit(1)
		}
	}

	log.Infof("Exiting")
}

func startSidecar(config *Config, log logrus.FieldLogger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	spiffeSidecar := sidecar.New(&sidecar.Config{
		AgentAddress:             config.AgentAddress,
		Cmd:                      config.Cmd,
		CmdArgs:                  config.CmdArgs,
		CertDir:                  config.CertDir,
		SvidFileName:             config.SvidFileName,
		SvidKeyFileName:          config.SvidKeyFileName,
		SvidBundleFileName:       config.SvidBundleFileName,
		Log:                      log,
		RenewSignal:              config.RenewSignal,
		AddIntermediatesToBundle: config.AddIntermediatesToBundle,
		//JwtSvids:                 config.JwtSvids.([]sidecar.JwtConfig),
		JWTBundleFilename: config.JWTBundleFilename,
	})

	return spiffeSidecar.RunDaemon(ctx)
}

func fetchX509Context(ctx context.Context, config *Config) error {
	x509Context, err := workloadapi.FetchX509Context(ctx, getWorkloadAPIAdress(config.AgentAddress))
	if err != nil {
		return err
	}

	return disk.WriteX509Context(x509Context, config.AddIntermediatesToBundle, config.IncludeFederatedDomains, config.CertDir, config.SvidFileName, config.SvidKeyFileName, config.SvidBundleFileName)
}
