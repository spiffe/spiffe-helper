package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc"
)

func main() {
	// 0. Load configuration
	// 1. Request certs using Workload API
	// 2. Put cert on disk
	// 3. Start the specified process if it is not running, otherwise send the configured signal to renew the certificates
	// 4. Wait until TTL/2
	// 5. Goto 1

	configFile := flag.String("config", "helper.conf", "<configFile> Configuration file path")
	flag.Parse()

	config, err := ParseConfig(*configFile)
	if err != nil {
		panic(fmt.Errorf("error parsing configuration file: %v\n%v", *configFile, err))
	}
	log("Sidecar is up! Will use agent at %s\n\n", config.AgentAddress)
	if config.Cmd == "" {
		log("Warning: no cmd defined to execute.\n")
	}
	log("Using configuration file: %v\n", *configFile)

	workloadClient, ctx, cancel, err := createGrpcClient(config)
	defer cancel()
	if err != nil {
		panic(fmt.Errorf("error creating GRPC client.\n%v", err))
	}

	sidecar := NewSidecar(ctx, config, workloadClient)

	err = sidecar.RunDaemon()
	if err != nil {
		panic(err)
	}
}

func createGrpcClient(config *SidecarConfig) (workloadClient workload.WorkloadClient, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx = context.Background()
	ctx, cancel = context.WithCancel(ctx)

	conn, err := grpc.Dial(config.AgentAddress,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))

	workloadClient = workload.NewWorkloadClient(conn)

	return workloadClient, ctx, cancel, err
}
