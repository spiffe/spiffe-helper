package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	testTimeSeconds = 20
	testTTL         = 10
)

// TestSidecar_Integration will run the sidecar with an 'echo' command
// and a simple webserver to mock the Workload API to the sidecar.
// The objetive is to make sure sidecar is requesting certs and invoking command successfully.
// TODO: 'echo' command exits immediately so we cannot test signalling. Improve this.
func TestSidecar_Integration(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "test-certs")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpdir)

	config := &SidecarConfig{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SvidFileName:       "svid.pem",
		SvidKeyFileName:    "svid_key.pem",
		SvidBundleFileName: "svid_bundle.pem",
	}

	fmt.Printf("Will test for %d seconds.\n", testTimeSeconds)
	go sendInterrupt(testTimeSeconds)

	workloadClient := MockWorkloadClient{}

	sidecar := NewSidecar(nil, config, workloadClient)

	err = sidecar.RunDaemon()
	if err != nil {
		panic(err)
	}
}

func sendInterrupt(seconds int) {
	time.Sleep(time.Second * time.Duration(seconds))
	fmt.Printf("Tested for %d seconds. Will interrupt!\n", testTimeSeconds)
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		panic(err)
	}
	err = p.Signal(os.Interrupt)
	if err != nil {
		panic(err)
	}
}

func readFile(file string) (bytes []byte) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return
}

type MockWorkloadClient struct {
}

func (m MockWorkloadClient) FetchAllBundles(ctx context.Context, in *workload.Empty, opts ...grpc.CallOption) (bundles *workload.Bundles, err error) {
	bundles = &workload.Bundles{
		Ttl: testTTL,
		Bundles: []*workload.WorkloadEntry{
			&workload.WorkloadEntry{
				SpiffeId:         "example.org/id",
				Svid:             readFile("keys/svid.pem"),
				SvidPrivateKey:   readFile("keys/svid_pk.pem"),
				SvidBundle:       readFile("keys/bundle.pem"),
				FederatedBundles: nil,
			},
		},
	}
	err = nil
	return
}

func (m MockWorkloadClient) FetchBundles(ctx context.Context, in *workload.SpiffeID, opts ...grpc.CallOption) (*workload.Bundles, error) {
	panic("Not implemented")
}
