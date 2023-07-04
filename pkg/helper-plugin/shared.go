package helper_plugin

import (
	context "context"

	"github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

type SpiffeHelperPlugin interface {
	PostConfigs(context.Context, *ConfigsRequest) (*Empty, error)
	mustEmbedUnimplementedSpiffeHelperServer()
}

type GRPCSpiffeHelperPlugin struct {
	plugin.Plugin
	Impl SpiffeHelperPlugin
}

func (p *GRPCSpiffeHelperPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterSpiffeHelperServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *GRPCSpiffeHelperPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewSpiffeHelperClient(c)}, nil
}

type GRPCClient struct {
	client SpiffeHelperClient
}

func (m *GRPCClient) PostConfigs(ctx context.Context, config *ConfigsRequest) (*Empty, error) {
	return m.client.PostConfigs(context.Background(), config)
}

func (m *GRPCClient) mustEmbedUnimplementedSpiffeHelperServer() {
}

type GRPCServer struct {
	Impl SpiffeHelperPlugin
}

func (m *GRPCServer) PostConfigs(ctx context.Context, config *ConfigsRequest) (*Empty, error) {
	_, err := m.Impl.PostConfigs(ctx, config)
	return &Empty{}, err
}

func (m *GRPCServer) mustEmbedUnimplementedSpiffeHelperServer() {
}

func GetHandshakeConfig() plugin.HandshakeConfig {
	return plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SPIFFE_HELPER",
		MagicCookieValue: "SPIFFE_HELPER",
	}
}

func GetPluginMap() map[string]plugin.Plugin {
	return map[string]plugin.Plugin{"plugin": &GRPCSpiffeHelperPlugin{}}
}
