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

func (s *SimplePlugin) LoadConfigs(ctx context.Context, request *pb.LoadConfigsRequest) (*pb.LoadConfigsResponse, error) {
	configs := request.Configs
	log.Printf("Message sent by %s to %s: %s", configs["from"], configs["to"], configs["message"])
	return &pb.LoadConfigsResponse{}, nil
}

func (s *SimplePlugin) UpdateX509SVID(ctx context.Context, request *pb.UpdateX509SVIDRequest) (*pb.UpdateX509SVIDResponse, error) {
	log.Printf("X.509 SVID updated")
	return &pb.UpdateX509SVIDResponse{}, nil
}

func (s *SimplePlugin) UpdateJWTSVID(ctx context.Context, request *pb.UpdateJWTSVIDRequest) (*pb.UpdateJWTSVIDResponse, error) {
	log.Printf("JWT SVID updated")
	return &pb.UpdateJWTSVIDResponse{}, nil
}

func (s *SimplePlugin) UpdateJWTBundle(ctx context.Context, request *pb.UpdateJWTBundleRequest) (*pb.UpdateJWTBundleResponse, error) {
	log.Printf("JWT bundle updated")
	return &pb.UpdateJWTBundleResponse{}, nil
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
