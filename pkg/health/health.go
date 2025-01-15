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
	HealthPath      string `hcl:"health_path"`
}

func StartHealthServer(healthCheckConfig CheckConfig, log logrus.FieldLogger, sidecar *sidecar.Sidecar) error {
	http.HandleFunc(healthCheckConfig.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		healthy := sidecar.CheckHealth()
		if healthy {
			_, err := w.Write([]byte(http.StatusText(http.StatusOK)))
			if err != nil {
			        log.WithError(err).Errorf("failed writing status text")
				return
			}
		} else {
			statusText := http.StatusText(http.StatusServiceUnavailable)
			b, err := json.Marshal(sidecar.GetFileWriteStatuses())
			if err != nil {
				statusText = string(b)
			}
			http.Error(w, statusText, http.StatusServiceUnavailable)
		}
	})
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(healthCheckConfig.BindPort),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
	return nil
}
