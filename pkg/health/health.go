package health

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
)

type CheckConfig struct {
	ListenerEnabled bool   `hcl:"listener_enabled"`
	BindPort        int    `hcl:"bind_port"`
	LivenessPath    string `hcl:"liveness_path"`
	ReadinessPath   string `hcl:"readiness_path"`
}

const (
	contentTypeJSON          = "application/json"
	contentTypePlainText     = "text/plain"
	statusOK                 = http.StatusOK
	statusServiceUnavailable = http.StatusServiceUnavailable
)

func StartHealthServer(healthCheckConfig CheckConfig, log logrus.FieldLogger, sidecar *sidecar.Sidecar) error {
	http.HandleFunc(healthCheckConfig.LivenessPath, func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, sidecar.CheckLiveness(), log, sidecar)
	})
	http.HandleFunc(healthCheckConfig.ReadinessPath, func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, sidecar.CheckReadiness(), log, sidecar)
	})
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(healthCheckConfig.BindPort),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
	return nil
}

type Response struct {
	Status string         `json:"status"`
	Health sidecar.Health `json:"health"`
}

func writeResponse(w http.ResponseWriter, goodStatus bool, log logrus.FieldLogger, sidecar *sidecar.Sidecar) {
	statusCode := statusOK
	statusText := http.StatusText(statusOK)

	if !goodStatus {
		statusCode = statusServiceUnavailable
		statusText = http.StatusText(statusServiceUnavailable)
	}

	response := Response{
		Status: statusText,
		Health: sidecar.GetHealth(),
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		log.WithError(err).Errorf("failed marshalling response")
		w.Header().Set("Content-Type", contentTypePlainText)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(statusText))
		if err != nil {
			log.WithError(err).Errorf("failed writing response text")
		}
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(statusCode)
	_, err = w.Write(jsonBytes)
	if err != nil {
		log.WithError(err).Errorf("failed writing response JSON")
	}
}
