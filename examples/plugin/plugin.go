package main

import (
	"context"
	"log"
	"os"
	"path"

	"github.com/hashicorp/go-plugin"
	pb "github.com/spiffe/spiffe-helper/pkg/notifier"
)

type SimplePlugin struct {
	pb.NotifierServer
	configs map[string]string
}

func writeSomething(path string) {
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteString("something"); err != nil {
		log.Fatal(err)
	}
}

func (s *SimplePlugin) LoadConfigs(ctx context.Context, request *pb.LoadConfigsRequest) (*pb.LoadConfigsResponse, error) {
	s.configs = request.Configs
	log.Printf("Plugin loaded")
	return &pb.LoadConfigsResponse{}, nil
}

func (s *SimplePlugin) UpdateX509SVID(ctx context.Context, request *pb.UpdateX509SVIDRequest) (*pb.UpdateX509SVIDResponse, error) {
	path := path.Join(s.configs["plugin_cert_dir"], s.configs["x509_svid_file_name"])
	writeSomething(path)
	log.Printf("X.509 SVID updated")
	return &pb.UpdateX509SVIDResponse{}, nil
}

func (s *SimplePlugin) UpdateJWTSVID(ctx context.Context, request *pb.UpdateJWTSVIDRequest) (*pb.UpdateJWTSVIDResponse, error) {
	path := path.Join(s.configs["plugin_cert_dir"], s.configs["jwt_svid_file_name"])
	writeSomething(path)
	log.Printf("JWT SVID updated")
	return &pb.UpdateJWTSVIDResponse{}, nil
}

func (s *SimplePlugin) UpdateJWTBundle(ctx context.Context, request *pb.UpdateJWTBundleRequest) (*pb.UpdateJWTBundleResponse, error) {
	path := path.Join(s.configs["plugin_cert_dir"], s.configs["jwt_bundle_file_name"])
	writeSomething(path)
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
