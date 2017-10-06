package main

import (
	"context"
	"net"
	"time"

	workload "github.com/spiffe/sidecar/wlapi"
	"google.golang.org/grpc"
)

const (
	configFile = "sidecar_config.hcl"
)

func main() {
	// 0. Load configuration
	// 1. Request certs using Workload API
	// 2. Put cert on disk
	// 3. Start ghostunnel if not running, otherwise send SIGUSR1 to reload cert
	// 4. Wait until TTL expires
	// 5. Goto 1

	config, err := ParseConfig(configFile)
	if err != nil {
		panic(err)
	}
	log("Sidecar is up! Will use agent at %s\n\n", config.AgentAddress)

	workloadClient, ctx, cancel, err := createGrpcClient(config)
	defer cancel()
	if err != nil {
		panic(err)
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

	return
}
