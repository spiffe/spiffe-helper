package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

func main() {
	// 0. Load configuration
	// 1. Create Sidecar
	// 2. Run Sidecar's Daemon

	log := logger.Std
	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	config, err := ParseConfig(*configFile)
	if err != nil {
		log.Errorf("error parsing configuration file: %v\n%v", *configFile, err)
		panic(err)
	}
	config.Log = log

	log.Infof("Connecting to agent at %q\n", config.AgentAddress)
	if config.Cmd == "" {
		log.Warnf("No cmd defined to execute.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Infof("Using configuration file: %q\n", *configFile)
	spiffeSidecar := sidecar.NewSidecar(config)

	err = spiffeSidecar.RunDaemon(ctx)
	if err != nil {
		panic(err)
	}

	log.Infof("Exiting")
}
