package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-plugin"
	pb "github.com/spiffe/spiffe-helper/pkg/helper-plugin"
)

type SimplePlugin struct {
	pb.SpiffeHelperServer
}

func (s *SimplePlugin) PostConfigs(ctx context.Context, request *pb.ConfigsRequest) (*pb.Empty, error) {
	configs := request.Configs

	fmt.Printf("From: %s\n", configs["from"])
	fmt.Printf("To: %s\n", configs["to"])
	fmt.Printf("Message: %s\n", configs["message"])

	return new(pb.Empty), nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: pb.GetHandshakeConfig(),
		Plugins: map[string]plugin.Plugin{
			"simplePlugin": &pb.GRPCSpiffeHelperPlugin{Impl: &SimplePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
