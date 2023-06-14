package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("/run/client/certs/svid.crt", "/run/client/certs/svid.key")
	if err != nil {
		log.Fatal(err)
	}

	ca, err := ioutil.ReadFile("/run/client/certs/root.crt")
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	var r *http.Response
	if os.Args[1] == "0" {
		r, err = client.Get("https://go-server:8080/getMail")
		if err != nil {
			os.Exit(1)
		}
	} else {
		r, err = http.Get("https://go-server:8080/hello")
		if err != nil {
			os.Exit(1)
		}
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	if string(body) == "test@user.com" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
