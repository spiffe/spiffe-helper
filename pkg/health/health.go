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

func StartHealthServer(healthCheckConfig CheckConfig, log logrus.FieldLogger, sidecar *sidecar.Sidecar) error {
	http.HandleFunc(healthCheckConfig.LivenessPath, func(w http.ResponseWriter, _ *http.Request) {
		liveness := sidecar.CheckLiveness()
		writeResponse(w, liveness, log, sidecar)
	})
	http.HandleFunc(healthCheckConfig.ReadinessPath, func(w http.ResponseWriter, _ *http.Request) {
		readiness := sidecar.CheckReadiness()
		writeResponse(w, readiness, log, sidecar)
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
	if goodStatus {
		response := http.StatusText(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		b, err := json.Marshal(Response{
			Status: response,
			Health: sidecar.GetHealth(),
		})
		if err != nil {
			log.WithError(err).Errorf("failed marshalling response")
		} else {
			response = string(b)
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(response))
		if err != nil {
			log.WithError(err).Errorf("failed writing status text")
			return
		}
	} else {
		response := http.StatusText(http.StatusServiceUnavailable)
		w.Header().Set("Content-Type", "plain/text")
		b, err := json.Marshal(Response{
			Status: response,
			Health: sidecar.GetHealth(),
		})
		if err != nil {
			log.WithError(err).Errorf("failed marshalling response")
		} else {
			response = string(b)
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, err = w.Write([]byte(response))
		if err != nil {
			log.WithError(err).Errorf("failed writing status text")
			return
		}
	}
}
