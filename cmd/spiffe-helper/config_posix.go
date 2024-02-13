package main

import (
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func validateOSConfig(*Config) error {
	return nil
}

func getWorkloadAPIAdress(agentAddress string) workloadapi.ClientOption {
	return workloadapi.WithAddr("unix://" + agentAddress)
}
