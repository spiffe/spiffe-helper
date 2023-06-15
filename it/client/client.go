package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("/run/client/certs/svid.crt", "/run/client/certs/svid.key")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	ca, err := os.ReadFile("/run/client/certs/root.crt")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      caPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	var r *http.Response
	var body []byte
	if os.Args[1] == "0" {
		r, err = client.Get("https://go-server:8080/getMail")
	} else {
		r, err = http.Get("https://go-server:8080/getMail")
	}

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	body, err = io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	err = r.Body.Close()

	if string(body) == "test@user.com" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}

}
