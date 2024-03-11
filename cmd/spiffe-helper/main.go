package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/pkg/disk"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

func main() {
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	//damonMode := flag.Bool("daemon_mode", true, "Exit once the requested objects are retrieved")
	flag.Parse()

	ctx := context.Background()
	log := logrus.WithField("system", "spiffe-helper")
	log.Infof("Using configuration file: %q", *configFile)

	config, err := ParseConfig(*configFile)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse %q", *configFile)
		os.Exit(1)
	}

	x509Enabled, jwtBundleEnabled, jwtSVIDsEnabled, err := ValidateConfig(config, log)
	if err != nil {
		log.WithError(err).Errorf("Invalid configuration")
		os.Exit(1)
	}

	if !*config.DaemonMode {
		log.Info("Daemon mode disabled")
		if x509Enabled {
			log.Info("Fetching x509 certificates")
			if err = fetchX509Context(ctx, config, log); err != nil {
				log.WithError(err).Error("Error fetching x509 certificates")
				os.Exit(1)
			}
			log.Info("Successfully fetched x509 certificates")
		}
		if jwtBundleEnabled {
			log.Info("Fetching JWT Bundle")
			if err = fetchJWTBundle(ctx, config); err != nil {
				log.WithError(err).Error("Error fetching JWT bundle")
				os.Exit(1)
			}
			log.Info("Successfully fetched JWT bundle")
		}
		if jwtSVIDsEnabled {
			log.Info("Fetching JWT SVIDs")
			if err = fetchJWTSVIDs(ctx, config); err != nil {
				log.WithError(err).Error("Error fetching JWT SVIDs")
				os.Exit(1)
			}
			log.Info("Successfully fetched JWT SVIDs")
		}
	} else {
		log.Info("Launching daemon")
		if err := startDaemon(config, log); err != nil {
			log.WithError(err).Error("Exiting due this error")
			os.Exit(1)
		}
	}

	log.Infof("Exiting")
	os.Exit(0)
}

func startDaemon(config *Config, log logrus.FieldLogger) error {
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

func fetchX509Context(ctx context.Context, config *Config, log *logrus.Entry) error {
	var x509Context *workloadapi.X509Context

	// Retry PermissionDenied errors. We may get a few of these before the cert is minted
	err := retry.OnError(wait.Backoff{
		Steps:    10,
		Duration: 10 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return status.Code(err) == codes.PermissionDenied
	}, func() (err error) {
		x509Context, err = workloadapi.FetchX509Context(ctx, getWorkloadAPIAdress(config.AgentAddress))
		return err

	})
	if err != nil {
		return err
	}

	return disk.WriteX509Context(x509Context, config.AddIntermediatesToBundle, config.IncludeFederatedDomains, config.CertDir, config.SvidFileName, config.SvidKeyFileName, config.SvidBundleFileName)
}

func fetchJWTBundle(ctx context.Context, config *Config) error {
	var jwtBundleSet *jwtbundle.Set

	// Retry PermissionDenied errors. We may get a few of these before the cert is minted
	err := retry.OnError(wait.Backoff{
		Steps:    10,
		Duration: 10 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return status.Code(err) == codes.PermissionDenied
	}, func() (err error) {
		jwtBundleSet, err = workloadapi.FetchJWTBundles(ctx, getWorkloadAPIAdress(config.AgentAddress))
		return err

	})
	if err != nil {
		return err
	}

	return disk.WriteJWTBundleSet(jwtBundleSet, config.CertDir, config.JWTBundleFilename)
}

func fetchJWTSVIDs(ctx context.Context, config *Config) error {
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(getWorkloadAPIAdress(config.AgentAddress)))
	if err != nil {
		return err
	}

	var errs []error
	for _, jwtConfig := range config.JWTSvids {
		if err = fetchJWTSVID(ctx, jwtSource, jwtConfig.JWTAudience, config.CertDir, jwtConfig.JWTSvidFilename); err != nil {
			errs = append(errs, fmt.Errorf("unable to JWT SVID for audience %q: %w", jwtConfig.JWTAudience, err))
		}
	}

	return errors.Join(errs...)
}

func fetchJWTSVID(ctx context.Context, jwtSource *workloadapi.JWTSource, audience, certDir, jwtSVIDFilename string) error {
	var jwtSVID *jwtsvid.SVID

	// Retry PermissionDenied errors. We may get a few of these before the cert is minted
	err := retry.OnError(wait.Backoff{
		Steps:    10,
		Duration: 10 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return status.Code(err) == codes.PermissionDenied
	}, func() (err error) {
		jwtSVID, err = jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
		return err

	})
	if err != nil {
		return err
	}

	return disk.WriteJWTSVID(jwtSVID, certDir, jwtSVIDFilename)
}
