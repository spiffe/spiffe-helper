package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func getMail(writer http.ResponseWriter, request *http.Request) {
	_, err := io.WriteString(writer, "test@user.com")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ca, err := os.ReadFile("/run/go-server/certs/root.crt")
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	http.HandleFunc("/getMail", getMail)

	server := &http.Server{
		Addr:              ":8080",
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Fatal(server.ListenAndServeTLS("/run/go-server/certs/svid.crt", "/run/go-server/certs/svid.key"))
}
