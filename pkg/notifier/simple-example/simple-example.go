package main

import (
	"context"
	"log"

	"github.com/hashicorp/go-plugin"
	pb "github.com/spiffe/spiffe-helper/pkg/notifier"
)

type SimplePlugin struct {
	pb.NotifierServer
}

func (s *SimplePlugin) LoadConfigs(ctx context.Context, request *pb.ConfigsRequest) (*pb.Empty, error) {
	configs := request.Configs
	log.Printf("Message sent by %s to %s: %s", configs["from"], configs["to"], configs["message"])
	return &pb.Empty{}, nil
}

func (s *SimplePlugin) UpdateX509SVID(ctx context.Context, empty *pb.Empty) (*pb.Empty, error) {
	log.Printf("Svid updated")
	return &pb.Empty{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: pb.GetHandshakeConfig(),
		Plugins: map[string]plugin.Plugin{
			"simplePlugin": &pb.GRPCNotifier{Impl: &SimplePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
