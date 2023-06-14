package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func getMail(writer http.ResponseWriter, request *http.Request) {
	io.WriteString(writer, "test@user.com")
}

func main() {
	ca, err := ioutil.ReadFile("/run/go-server/certs/root.crt")
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	http.HandleFunc("/getMail", getMail)

	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS("/run/go-server/certs/svid.crt", "/run/go-server/certs/svid.key"))
}
