package notifier

import (
	context "context"

	"github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

type Notifier interface {
	LoadConfigs(context.Context, *ConfigsRequest) (*Empty, error)
	UpdateX509SVID(context.Context, *Empty) (*Empty, error)
	mustEmbedUnimplementedNotifierServer()
}

type GRPCNotifier struct {
	plugin.Plugin
	Impl Notifier
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

func (m *GRPCClient) LoadConfigs(ctx context.Context, config *ConfigsRequest) (*Empty, error) {
	return m.client.LoadConfigs(context.Background(), config)
}

func (m *GRPCClient) UpdateX509SVID(ctx context.Context, empty *Empty) (*Empty, error) {
	return m.client.UpdateX509SVID(context.Background(), empty)
}

func (m *GRPCClient) mustEmbedUnimplementedNotifierServer() {
}

type GRPCServer struct {
	Impl Notifier
}

func (m *GRPCServer) LoadConfigs(ctx context.Context, config *ConfigsRequest) (*Empty, error) {
	_, err := m.Impl.LoadConfigs(ctx, config)
	return &Empty{}, err
}

func (m *GRPCServer) UpdateX509SVID(ctx context.Context, empty *Empty) (*Empty, error) {
	_, err := m.Impl.UpdateX509SVID(ctx, empty)
	return &Empty{}, err
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
