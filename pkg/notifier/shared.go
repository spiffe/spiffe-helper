package notifier

import (
	context "context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

type GRPCNotifier struct {
	plugin.Plugin
	Impl NotifierServer
}

func (p *GRPCNotifier) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterNotifierServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *GRPCNotifier) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNotifierClient(c)}, nil
}

type GRPCClient struct {
	client NotifierClient
}

func (m *GRPCClient) LoadConfigs(ctx context.Context, config *LoadConfigsRequest) (*LoadConfigsResponse, error) {
	return m.client.LoadConfigs(ctx, config)
}

func (m *GRPCClient) UpdateX509SVID(ctx context.Context, empty *UpdateX509SVIDRequest) (*UpdateX509SVIDResponse, error) {
	return m.client.UpdateX509SVID(ctx, empty)
}

func (m *GRPCClient) UpdateJWTSVID(ctx context.Context, empty *UpdateJWTSVIDRequest) (*UpdateJWTSVIDResponse, error) {
	return m.client.UpdateJWTSVID(ctx, empty)
}

func (m *GRPCClient) UpdateJWTBundle(ctx context.Context, empty *UpdateJWTBundleRequest) (*UpdateJWTBundleResponse, error) {
	return m.client.UpdateJWTBundle(ctx, empty)
}

func (m *GRPCClient) mustEmbedUnimplementedNotifierServer() {
}

type GRPCServer struct {
	Impl NotifierServer
}

func (m *GRPCServer) LoadConfigs(ctx context.Context, request *LoadConfigsRequest) (*LoadConfigsResponse, error) {
	_, err := m.Impl.LoadConfigs(ctx, request)
	return &LoadConfigsResponse{}, err
}

func (m *GRPCServer) UpdateX509SVID(ctx context.Context, request *UpdateX509SVIDRequest) (*UpdateX509SVIDResponse, error) {
	_, err := m.Impl.UpdateX509SVID(ctx, request)
	return &UpdateX509SVIDResponse{}, err
}

func (m *GRPCServer) UpdateJWTSVID(ctx context.Context, request *UpdateJWTSVIDRequest) (*UpdateJWTSVIDResponse, error) {
	_, err := m.Impl.UpdateJWTSVID(ctx, request)
	return &UpdateJWTSVIDResponse{}, err
}

func (m *GRPCServer) UpdateJWTBundle(ctx context.Context, request *UpdateJWTBundleRequest) (*UpdateJWTBundleResponse, error) {
	_, err := m.Impl.UpdateJWTBundle(ctx, request)
	return &UpdateJWTBundleResponse{}, err
}

func (m *GRPCServer) mustEmbedUnimplementedNotifierServer() {
}

func GetHandshakeConfig() plugin.HandshakeConfig {
	return plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "NOTIFIER",
		MagicCookieValue: "NOTIFIER",
	}
}

func GetPluginMap() map[string]plugin.Plugin {
	return map[string]plugin.Plugin{"plugin": &GRPCNotifier{}}
}

func GetSecureConfig(checksum string) (*plugin.SecureConfig, error) {
	sum, err := hex.DecodeString(checksum)
	if err != nil {
		return nil, fmt.Errorf("checksum is not a valid hex string")
	}

	hash := sha256.New()
	if len(sum) != hash.Size() {
		return nil, fmt.Errorf("expected checksum of length %d; got %d", hash.Size()*2, len(sum)*2)
	}

	return &plugin.SecureConfig{Checksum: sum, Hash: sha256.New()}, nil
}
