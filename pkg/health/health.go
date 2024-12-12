package health

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/cmd/spiffe-helper/config"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"net/http"
	"strconv"
	"time"
)

func StartHealthServer(configFile string, daemonModeFlag bool, log logrus.FieldLogger, sidecar *sidecar.Sidecar) error {
	hclConfig, err := config.ParseConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", configFile, err)
	}
	hclConfig.ParseConfigFlagOverrides(daemonModeFlag, config.DaemonModeFlagName)
	if err := hclConfig.ValidateConfig(log); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if *hclConfig.DaemonMode && *hclConfig.HealthCheck.EnableHealthCheck {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			healthy := sidecar.CheckHealth()
			if healthy {
				_, err := w.Write([]byte(http.StatusText(http.StatusOK)))
				log.Error(err)
				if err != nil {
					return
				}
			} else {
				statusText := http.StatusText(http.StatusServiceUnavailable)
				b, err := json.Marshal(sidecar.GetFileWritesSuccess())
				if err != nil {
					statusText = string(b)
				}
				http.Error(w, statusText, http.StatusServiceUnavailable)
			}
		})
		server := &http.Server{
			Addr:              ":" + strconv.Itoa(hclConfig.HealthCheck.HealthCheckPort),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
		}
		log.Fatal(server.ListenAndServe())
	}
	return nil
}
