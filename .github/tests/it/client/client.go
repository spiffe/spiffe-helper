package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const serverURL = "https://go-server:8080/getMail"

func main() {
	presentClientSVID := flag.Bool("client-svid", false, "present the client SVID during the TLS handshake")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	ca, err := os.ReadFile("/run/client/certs/root.crt")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		log.Println("failed to parse root certificate")
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caPool,
	}
	if *presentClientSVID {
		cert, err := tls.LoadX509KeyPair("/run/client/certs/svid.crt", "/run/client/certs/svid.key")
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	response, err := client.Get(serverURL)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if string(body) != "test@user.com" {
		log.Printf("unexpected response body %q", body)
		os.Exit(1)
	}

	fmt.Println(string(body))
}
