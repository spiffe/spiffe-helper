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

func writeResponse(w http.ResponseWriter, goodStatus bool, log logrus.FieldLogger, sidecar *sidecar.Sidecar) {
	if goodStatus {
		_, err := w.Write([]byte(http.StatusText(http.StatusOK)))
		if err != nil {
			log.WithError(err).Errorf("failed writing status text")
			return
		}
	} else {
		statusText := http.StatusText(http.StatusServiceUnavailable)
		b, err := json.Marshal(sidecar.GetHealth())
		if err != nil {
			statusText = string(b)
		}
		http.Error(w, statusText, http.StatusServiceUnavailable)
	}
}
