package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"

	env "github.com/caarlos0/env/v11"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/pkg/health"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"gopkg.in/yaml.v3"
)

const (
	configFormatAuto         = "auto"
	configFormatHCL          = "hcl"
	configFormatJSON         = "json"
	configFormatYAML         = "yaml"
	envPrefix                = "SPIFFE_HLP_"
	defaultAgentAddress      = "/tmp/spire-agent/public/api.sock"
	defaultCertFileMode      = FileMode(0644)
	defaultKeyFileMode       = FileMode(0600)
	defaultJWTBundleFileMode = FileMode(0600)
	defaultJWTSVIDFileMode   = FileMode(0600)
	defaultBindPort          = 8081
	defaultLivenessPath      = "/live"
	defaultReadinessPath     = "/ready"
)

type FileMode int

type Config struct {
	AddIntermediatesToBundle bool          `hcl:"add_intermediates_to_bundle" yaml:"add_intermediates_to_bundle" env:"ADD_INTERMEDIATES_TO_BUNDLE"`
	AgentAddress             string        `hcl:"agent_address" yaml:"agent_address" env:"AGENT_ADDRESS"`
	Cmd                      string        `hcl:"cmd" yaml:"cmd" env:"CMD"`
	CmdArgs                  string        `hcl:"cmd_args" yaml:"cmd_args" env:"CMD_ARGS"`
	PIDFilename              string        `hcl:"pid_file_name" yaml:"pid_file_name" env:"PID_FILE_NAME"`
	CertDir                  string        `hcl:"cert_dir" yaml:"cert_dir" env:"CERT_DIR"`
	CertFileMode             FileMode      `hcl:"cert_file_mode" yaml:"cert_file_mode" env:"CERT_FILE_MODE"`
	KeyFileMode              FileMode      `hcl:"key_file_mode" yaml:"key_file_mode" env:"KEY_FILE_MODE"`
	JWTBundleFileMode        FileMode      `hcl:"jwt_bundle_file_mode" yaml:"jwt_bundle_file_mode" env:"JWT_BUNDLE_FILE_MODE"`
	JWTSVIDFileMode          FileMode      `hcl:"jwt_svid_file_mode" yaml:"jwt_svid_file_mode" env:"JWT_SVID_FILE_MODE"`
	IncludeFederatedDomains  bool          `hcl:"include_federated_domains" yaml:"include_federated_domains" env:"INCLUDE_FEDERATED_DOMAINS"`
	OmitExpired              bool          `hcl:"omit_expired" yaml:"omit_expired" env:"OMIT_EXPIRED"`
	RenewSignal              string        `hcl:"renew_signal" yaml:"renew_signal" env:"RENEW_SIGNAL"`
	DaemonMode               *bool         `hcl:"daemon_mode" yaml:"daemon_mode" env:"DAEMON_MODE"`
	HealthCheck              health.Config `hcl:"health_checks" yaml:"health_checks" envPrefix:"HEALTH_"`
	Hint                     string        `hcl:"hint" yaml:"hint" env:"HINT"`
	LogLevel                 string        `hcl:"log_level" yaml:"log_level" env:"LOG_LEVEL"`

	// x509 configuration
	SVIDFilename       string `hcl:"svid_file_name" yaml:"svid_file_name" env:"SVID_FILE_NAME"`
	SVIDKeyFilename    string `hcl:"svid_key_file_name" yaml:"svid_key_file_name" env:"SVID_KEY_FILE_NAME"`
	SVIDBundleFilename string `hcl:"svid_bundle_file_name" yaml:"svid_bundle_file_name" env:"SVID_BUNDLE_FILE_NAME"`

	// JWT configuration
	// SPIFFE_HLP_JWT_SVIDS accepts a YAML/JSON array and replaces file-configured entries.
	JWTSVIDs          []JWTConfig `hcl:"jwt_svids" yaml:"jwt_svids" env:"JWT_SVIDS"`
	JWTBundleFilename string      `hcl:"jwt_bundle_file_name" yaml:"jwt_bundle_file_name" env:"JWT_BUNDLE_FILE_NAME"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

type JWTConfig struct {
	JWTAudience       string   `hcl:"jwt_audience" yaml:"jwt_audience"`
	JWTExtraAudiences []string `hcl:"jwt_extra_audiences" yaml:"jwt_extra_audiences"`
	JWTSVIDFilename   string   `hcl:"jwt_svid_file_name" yaml:"jwt_svid_file_name"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" yaml:"-"`
}

func ParseConfig(configFile string, configFormat string, daemonModeFlag bool, daemonModeFlagName string) (*Config, error) {
	if configFile == "" || !configFileExists(configFile) || configFileEmpty(configFile) {
		helperConfig, err := loadConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration from environment: %w", err)
		}
		helperConfig.parseConfigFlagOverrides(daemonModeFlag, daemonModeFlagName)
		return helperConfig, nil
	}

	helperConfig, err := parseConfigFile(configFile, configFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration file %q: %w", configFile, err)
	}
	helperConfig.parseConfigFlagOverrides(daemonModeFlag, daemonModeFlagName)
	return helperConfig, nil
}

func (c *Config) ValidateConfig(log logrus.FieldLogger) error {
	if err := c.checkForUnknownConfig(); err != nil {
		return err
	}

	if err := validateOSConfig(c); err != nil {
		return err
	}

	for _, jwtConfig := range c.JWTSVIDs {
		if jwtConfig.JWTSVIDFilename == "" {
			return errors.New("'jwt_file_name' is required in 'jwt_svids'")
		}
		if jwtConfig.JWTAudience == "" {
			return errors.New("'jwt_audience' is required in 'jwt_svids'")
		}
	}

	if c.AgentAddress == "" {
		if spiffeEndpointSocket := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); spiffeEndpointSocket != "" {
			c.AgentAddress = spiffeEndpointSocket
		} else {
			c.AgentAddress = defaultAgentAddress
		}
	}

	if c.DaemonMode != nil && !*c.DaemonMode {
		if c.Cmd != "" {
			log.Warn("cmd is set but daemon_mode is false. cmd will be ignored. This may become an error in a future release.")
		}
		if c.RenewSignal != "" {
			log.Warn("renew_signal is set but daemon_mode is false. renew_signal will be ignored. This may become an error in a future release.")
		}
		// pid_file_name is new enough that there should not be existing configurations that use it without daemon_mode
		// so we can error here without backcompat worries. In future we may support one-shot signalling of a process, but
		// it's ignored at the moment so we shouldn't allow the user to think it's doing something.
		if c.PIDFilename != "" {
			return errors.New("pid_file_name is set but daemon_mode is false. pid_file_name is only supported in daemon_mode")
		}
	}

	if c.PIDFilename != "" && c.RenewSignal == "" {
		return errors.New("must specify renew_signal when using pid_file_name")
	}

	x509Enabled, err := validateX509Config(c)
	if err != nil {
		return err
	}

	jwtBundleEnabled, jwtSVIDsEnabled := validateJWTConfig(c)

	if !x509Enabled && !jwtBundleEnabled && !jwtSVIDsEnabled {
		return errors.New("at least one of the sets ('svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name'), 'jwt_svids', or 'jwt_bundle_file_name' must be fully specified")
	}

	if c.CertFileMode < 0 {
		return errors.New("cert file mode must be positive")
	} else if c.CertFileMode == 0 {
		c.CertFileMode = defaultCertFileMode
	}
	if c.KeyFileMode < 0 {
		return errors.New("key file mode must be positive")
	} else if c.KeyFileMode == 0 {
		c.KeyFileMode = defaultKeyFileMode
	}
	if c.JWTBundleFileMode < 0 {
		return errors.New("jwt bundle file mode must be positive")
	} else if c.JWTBundleFileMode == 0 {
		c.JWTBundleFileMode = defaultJWTBundleFileMode
	}
	if c.JWTSVIDFileMode < 0 {
		return errors.New("jwt svid file mode must be positive")
	} else if c.JWTSVIDFileMode == 0 {
		c.JWTSVIDFileMode = defaultJWTSVIDFileMode
	}

	if c.HealthCheck.ListenerEnabled {
		if c.HealthCheck.BindPort < 0 {
			return errors.New("bind port must be positive")
		}
		if c.HealthCheck.BindPort == 0 {
			c.HealthCheck.BindPort = defaultBindPort
		}
		if c.HealthCheck.LivenessPath == "" {
			c.HealthCheck.LivenessPath = defaultLivenessPath
		}
		if c.HealthCheck.ReadinessPath == "" {
			c.HealthCheck.ReadinessPath = defaultReadinessPath
		}
	}

	return nil
}

func NewSidecarConfig(config *Config, log logrus.FieldLogger) *sidecar.Config {
	sidecarConfig := &sidecar.Config{
		AddIntermediatesToBundle: config.AddIntermediatesToBundle,
		AgentAddress:             config.AgentAddress,
		Cmd:                      config.Cmd,
		CmdArgs:                  config.CmdArgs,
		PIDFilename:              config.PIDFilename,
		CertDir:                  config.CertDir,
		CertFileMode:             fs.FileMode(config.CertFileMode),      //nolint:gosec
		KeyFileMode:              fs.FileMode(config.KeyFileMode),       //nolint:gosec
		JWTBundleFileMode:        fs.FileMode(config.JWTBundleFileMode), //nolint:gosec
		JWTSVIDFileMode:          fs.FileMode(config.JWTSVIDFileMode),   //nolint:gosec
		IncludeFederatedDomains:  config.IncludeFederatedDomains,
		OmitExpired:              config.OmitExpired,
		JWTBundleFilename:        config.JWTBundleFilename,
		Log:                      log,
		RenewSignal:              config.RenewSignal,
		SVIDFilename:             config.SVIDFilename,
		SVIDKeyFilename:          config.SVIDKeyFilename,
		SVIDBundleFilename:       config.SVIDBundleFilename,
		Hint:                     config.Hint,
	}

	for _, jwtSVID := range config.JWTSVIDs {
		sidecarConfig.JWTSVIDs = append(sidecarConfig.JWTSVIDs, sidecar.JWTConfig{
			JWTAudience:       jwtSVID.JWTAudience,
			JWTExtraAudiences: jwtSVID.JWTExtraAudiences,
			JWTSVIDFilename:   jwtSVID.JWTSVIDFilename,
		})
	}

	return sidecarConfig
}

// parseConfigFile parses a file into a Config struct.
func parseConfigFile(file string, configFormat string) (*Config, error) {
	if !configFileExists(file) {
		return nil, fmt.Errorf("configuration file does not exist: %s", file)
	}

	if configFormat == configFormatAuto {
		configFormat = detectConfigFormat(file)
	}

	switch configFormat {
	case configFormatHCL:
		return parseHCLFileAndApplyEnv(file)
	case configFormatJSON, configFormatYAML:
		return parseStructuredConfigFile(file)
	default:
		return nil, fmt.Errorf("invalid config format: %s", configFormat)
	}
}

// parseStructuredConfigFile parses YAML/JSON config into a Config struct.
// JSON config files use this path because JSON is valid YAML.
func parseStructuredConfigFile(file string) (*Config, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	config := new(Config)
	decoder := yaml.NewDecoder(bytes.NewReader(dat))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	if err := applyEnvOverrides(config); err != nil {
		return nil, err
	}
	return config, nil
}

// parseHCLConfigFile parses the given HCL file into a Config struct.
func parseHCLConfigFile(file string) (*Config, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	config := new(Config)
	if err := hcl.Decode(config, string(dat)); err != nil {
		return nil, err
	}
	return config, nil
}

func parseHCLFileAndApplyEnv(file string) (*Config, error) {
	config, err := parseHCLConfigFile(file)
	if err != nil {
		return nil, err
	}
	if err := applyEnvOverrides(config); err != nil {
		return nil, err
	}
	return config, nil
}

// applyEnvOverrides applies environment-based config on top of the parsed file config.
func applyEnvOverrides(config *Config) error {
	if err := env.ParseWithOptions(config, env.Options{
		Prefix: envPrefix,
		FuncMap: map[reflect.Type]env.ParserFunc{
			reflect.TypeOf([]JWTConfig{}): parseJWTSVIDsEnv,
			reflect.TypeOf(FileMode(0)):   parseFileModeEnv,
		},
	}); err != nil {
		return err
	}
	return nil
}

// loadConfigFromEnv loads configuration entirely from environment variables.
// This is used when no config file is provided.
func loadConfigFromEnv() (*Config, error) {
	config := new(Config)
	if err := applyEnvOverrides(config); err != nil {
		return nil, err
	}
	return config, nil
}

// parseConfigFlagOverrides handles command line arguments that override config file settings.
func (c *Config) parseConfigFlagOverrides(daemonModeFlag bool, daemonModeFlagName string) {
	if isFlagPassed(daemonModeFlagName) {
		// If daemon mode is set by CLI this takes precedence
		c.DaemonMode = &daemonModeFlag
	} else if c.DaemonMode == nil {
		// If daemon mode is not set, then default to true
		daemonMode := true
		c.DaemonMode = &daemonMode
	}
}

func configFileExists(file string) bool {
	if file == "" {
		return false
	}

	_, err := os.Stat(file)
	return err == nil
}

func configFileEmpty(file string) bool {
	info, err := os.Stat(file)
	return err == nil && info.Size() == 0
}

func detectConfigFormat(file string) string {
	switch {
	case strings.HasSuffix(file, ".conf"):
		return configFormatHCL
	case strings.HasSuffix(file, ".json"):
		return configFormatJSON
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		return configFormatYAML
	default:
		return configFormatHCL
	}
}

// checkForUnknownConfig looks for any unknown configuration keys and returns an error if one is found
func (c *Config) checkForUnknownConfig() error {
	if len(c.UnusedKeyPositions) != 0 {
		return fmt.Errorf("unknown top level key(s): %s", mapKeysToString(c.UnusedKeyPositions))
	}

	for i, jwtSVID := range c.JWTSVIDs {
		if len(jwtSVID.UnusedKeyPositions) != 0 {
			return fmt.Errorf("unknown key(s) in jwt_svids[%d]: %s", i, mapKeysToString(jwtSVID.UnusedKeyPositions))
		}
	}

	return nil
}

func validateX509Config(c *Config) (bool, error) {
	x509EmptyCount := countEmpty(c.SVIDFilename, c.SVIDBundleFilename, c.SVIDKeyFilename)
	if x509EmptyCount != 0 && x509EmptyCount != 3 {
		return false, errors.New("all or none of 'svid_file_name', 'svid_key_file_name', 'svid_bundle_file_name' must be specified")
	}

	return x509EmptyCount == 0, nil
}

func validateJWTConfig(c *Config) (bool, bool) {
	jwtBundleEmptyCount := countEmpty(c.JWTBundleFilename)

	return jwtBundleEmptyCount == 0, len(c.JWTSVIDs) > 0
}

func countEmpty(configs ...string) int {
	cnt := 0
	for _, config := range configs {
		if config == "" {
			cnt++
		}
	}

	return cnt
}

// isFlagPassed tests to see if a command line argument was set at all or left empty
func isFlagPassed(name string) bool {
	var found bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})

	return found
}

// mapKeysToString returns a comma separated string with all the keys from a map
func mapKeysToString[V any](myMap map[string]V) string {
	keys := make([]string, 0, len(myMap))
	for key := range myMap {
		keys = append(keys, key)
	}

	slices.Sort(keys)
	return strings.Join(keys, ",")
}
