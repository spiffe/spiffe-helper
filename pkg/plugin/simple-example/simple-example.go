package main

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/spiffe/spiffe-helper/pkg/plugin"
	"google.golang.org/grpc"
)

type simpleExampleServer struct {
	pb.SpiffeHelperServer
}

func (s *simpleExampleServer) PostConfigs(ctx context.Context, request *pb.ConfigsRequest) (*pb.Empty, error) {
	configs := request.Configs

	fmt.Printf("From: %s\n", configs["from"])
	fmt.Printf("To: %s\n", configs["to"])
	fmt.Printf("Message: %s\n", configs["message"])

	return new(pb.Empty), nil
}

func main() {
	lis, err := net.Listen("tcp", "localhost:8081")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	simpleExampleServer := &simpleExampleServer{}
	pb.RegisterSpiffeHelperServer(grpcServer, simpleExampleServer)
	log.Printf("server listening at %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
