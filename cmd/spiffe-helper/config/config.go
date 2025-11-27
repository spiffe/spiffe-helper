package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-helper/pkg/health"
	"github.com/spiffe/spiffe-helper/pkg/sidecar"
	"github.com/stretchr/testify/assert/yaml"
)

const (
	defaultAgentAddress      = "/tmp/spire-agent/public/api.sock"
	defaultCertFileMode      = 0644
	defaultKeyFileMode       = 0600
	defaultJWTBundleFileMode = 0600
	defaultJWTSVIDFileMode   = 0600
	defaultBindPort          = 8081
	defaultLivenessPath      = "/live"
	defaultReadinessPath     = "/ready"
)

type Config struct {
	AddIntermediatesToBundle bool   `hcl:"add_intermediates_to_bundle" json:"add_intermediates_to_bundle" yaml:"add_intermediates_to_bundle" env:"SPIFFE_HLP_ADD_INTERMEDIATES_TO_BUNDLE"`
	AgentAddress             string `hcl:"agent_address" json:"agent_address" yaml:"agent_address" env:"SPIFFE_HLP_AGENT_ADDRESS"`
	Cmd                      string `hcl:"cmd" json:"cmd" yaml:"cmd" env:"SPIFFE_HLP_CMD"`
	CmdArgs                  string `hcl:"cmd_args" json:"cmd_args" yaml:"cmd_args" env:"SPIFFE_HLP_CMD_ARGS"`
	PIDFilename              string `hcl:"pid_file_name" json:"pid_file_name" yaml:"pid_file_name" env:"SPIFFE_HLP_PID_FILE_NAME"`
	CertDir                  string `hcl:"cert_dir" json:"cert_dir" yaml:"cert_dir" env:"SPIFFE_HLP_CERT_DIR"`
	CertFileMode             int    `hcl:"cert_file_mode" json:"cert_file_mode" yaml:"cert_file_mode" env:"SPIFFE_HLP_CERT_FILE_MODE"`
	KeyFileMode              int    `hcl:"key_file_mode" json:"key_file_mode" yaml:"key_file_mode" env:"SPIFFE_HLP_KEY_FILE_MODE"`
	JWTBundleFileMode        int    `hcl:"jwt_bundle_file_mode" json:"jwt_bundle_file_mode" yaml:"jwt_bundle_file_mode" env:"SPIFFE_HLP_JWT_BUNDLE_FILE_MODE"`
	JWTSVIDFileMode          int    `hcl:"jwt_svid_file_mode" json:"jwt_svid_file_mode" yaml:"jwt_svid_file_mode" env:"SPIFFE_HLP_JWT_SVID_FILE_MODE"`
	IncludeFederatedDomains  bool   `hcl:"include_federated_domains" json:"include_federated_domains" yaml:"include_federated_domains" env:"SPIFFE_HLP_INCLUDE_FEDERATED_DOMAINS"`
	OmitExpired              bool   `hcl:"omit_expired" json:"omit_expired" yaml:"omit_expired" env:"SPIFFE_HLP_OMIT_EXPIRED"`
	RenewSignal              string `hcl:"renew_signal" json:"renew_signal" yaml:"renew_signal" env:"SPIFFE_HLP_RENEW_SIGNAL"`
	// Note: DaemonMode does not have an env tag because cleanenv doesn't support *bool types.
	// Instead, use populateDaemonModeFromEnv for environment variable support.
	DaemonMode  *bool         `hcl:"daemon_mode" json:"daemon_mode" yaml:"daemon_mode"`
	HealthCheck health.Config `hcl:"health_checks" json:"health_checks" yaml:"health_checks" env:"SPIFFE_HLP_HEALTH_CHECKS"`
	Hint        string        `hcl:"hint" json:"hint" yaml:"hint" env:"SPIFFE_HLP_HINT"`
	LogLevel    string        `hcl:"log_level" json:"log_level" yaml:"log_level" env:"SPIFFE_HLP_LOG_LEVEL"`

	// x509 configuration
	SVIDFilename       string `hcl:"svid_file_name" json:"svid_file_name" yaml:"svid_file_name" env:"SPIFFE_HLP_SVID_FILE_NAME"`
	SVIDKeyFilename    string `hcl:"svid_key_file_name" json:"svid_key_file_name" yaml:"svid_key_file_name" env:"SPIFFE_HLP_SVID_KEY_FILE_NAME"`
	SVIDBundleFilename string `hcl:"svid_bundle_file_name" json:"svid_bundle_file_name" yaml:"svid_bundle_file_name" env:"SPIFFE_HLP_SVID_BUNDLE_FILE_NAME"`

	// JWT configuration
	// Note: JWTSVIDs does not have an env tag because cleanenv doesn't support arrays of structs.
	// Instead, use indexed environment variables (see populateJWTSVIDsFromEnv for details).
	JWTSVIDs          []JWTConfig `hcl:"jwt_svids" json:"jwt_svids" yaml:"jwt_svids"`
	JWTBundleFilename string      `hcl:"jwt_bundle_file_name" json:"jwt_bundle_file_name" yaml:"jwt_bundle_file_name" env:"SPIFFE_HLP_JWT_BUNDLE_FILE_NAME"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" json:"-" yaml:"-"`
}

type JWTConfig struct {
	// Note: JWTConfig fields do not have env tags because cleanenv doesn't support arrays of structs.
	// Instead, use indexed environment variables (see populateJWTSVIDsFromEnv for details).
	JWTAudience       string   `hcl:"jwt_audience" json:"jwt_audience" yaml:"jwt_audience"`
	JWTExtraAudiences []string `hcl:"jwt_extra_audiences" json:"jwt_extra_audiences" yaml:"jwt_extra_audiences"`
	JWTSVIDFilename   string   `hcl:"jwt_svid_file_name" json:"jwt_svid_file_name" yaml:"jwt_svid_file_name"`

	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" json:"-" yaml:"-"`
}

// ParseConfigFile parses the given HCL file into a Config struct
func ParseConfigFile(file string, configFormat string) (*Config, error) {
	// Check if file is empty or doesn't exist
	fileExists := file != ""
	if fileExists {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fileExists = false
		}
	}

	switch configFormat {
	case "hcl":
		if !fileExists {
			return nil, fmt.Errorf("HCL format requires a configuration file, but file does not exist: %s", file)
		}
		return ParseHCLConfigFile(file)
	case "json", "yaml":
		// ProcessConfigFileAndEnv handles empty/missing files by using env vars
		return ProcessConfigFileAndEnv(file)
	case "auto":
		return ParseAutoConfigFile(file)
	default:
		return nil, fmt.Errorf("invalid config format: %s", configFormat)
	}
}

// ParseAutoConfigFile parses the given config file into a Config struct based on the file extension
func ParseAutoConfigFile(file string) (*Config, error) {
	// Check if file is empty or doesn't exist
	if file == "" {
		// Default to env-only mode (treat as YAML format for cleanenv)
		return ProcessConfigFileAndEnv("")
	}

	// Check if file exists
	if _, err := os.Stat(file); os.IsNotExist(err) {
		// File doesn't exist: default to env-only mode (treat as YAML format for cleanenv)
		return ProcessConfigFileAndEnv("")
	}

	// File exists: determine format by extension
	if strings.HasSuffix(file, ".conf") {
		return ParseHCLConfigFile(file)
	} else if strings.HasSuffix(file, ".json") || strings.HasSuffix(file, ".yaml") || strings.HasSuffix(file, ".yml") {
		return ProcessConfigFileAndEnv(file)
	}

	return nil, fmt.Errorf("invalid config file: %s. Supported formats: hcl, json, yaml", file)
}

// ParseYAMLConfigFile parses the given YAML file into a Config struct
func ParseYAMLConfigFile(file string) (*Config, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	config := new(Config)
	if err := yaml.Unmarshal(dat, config); err != nil {
		return nil, err
	}
	return config, nil
}

// loadConfigFromEnv loads configuration entirely from environment variables.
// This is used when no config file is provided or the file doesn't exist.
func loadConfigFromEnv(config *Config) error {
	// Use cleanenv to read from environment variables only
	if err := cleanenv.ReadEnv(config); err != nil {
		return err
	}
	// Parse indexed JWTSVIDs from environment variables
	if err := populateJWTSVIDsFromEnv(config); err != nil {
		return err
	}
	// Parse DaemonMode from environment variable (cleanenv doesn't support *bool)
	if err := populateDaemonModeFromEnv(config); err != nil {
		return err
	}
	return nil
}

// ProcessConfigFileAndEnv parses the given JSON or YAML file into a Config struct
func ProcessConfigFileAndEnv(file string) (*Config, error) {
	config := new(Config)

	// Check if file is empty or doesn't exist
	if file == "" {
		if err := loadConfigFromEnv(config); err != nil {
			return nil, err
		}
		return config, nil
	}

	// Check if file exists
	if _, err := os.Stat(file); os.IsNotExist(err) {
		if err := loadConfigFromEnv(config); err != nil {
			return nil, err
		}
		return config, nil
	}

	// File exists: read and parse it
	dat, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Determine format and unmarshal into map to detect unknown keys
	var dataMap map[string]interface{}
	switch {
	case strings.HasSuffix(file, ".json"):
		if err := json.Unmarshal(dat, &dataMap); err != nil {
			return nil, err
		}
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		if err := yaml.Unmarshal(dat, &dataMap); err != nil {
			return nil, err
		}
	default:
		// Try both JSON and YAML
		if err := json.Unmarshal(dat, &dataMap); err != nil {
			if err := yaml.Unmarshal(dat, &dataMap); err != nil {
				return nil, fmt.Errorf("failed to parse as JSON or YAML: %w", err)
			}
		}
	}

	if err := cleanenv.ReadConfig(file, config); err != nil {
		return nil, err
	}

	// Parse indexed JWTSVIDs from environment variables (will override file-based JWTSVIDs if present)
	if err := populateJWTSVIDsFromEnv(config); err != nil {
		return nil, err
	}

	// Parse DaemonMode from environment variable (cleanenv doesn't support *bool)
	// This will override file-based DaemonMode if present
	if err := populateDaemonModeFromEnv(config); err != nil {
		return nil, err
	}

	// Detect and populate unknown keys (only when file is provided)
	populateUnusedKeyPositions(config, dataMap)

	return config, nil
}

// populateUnusedKeyPositions detects unknown keys in JSON/YAML configs and populates UnusedKeyPositions
// to match the behavior of HCL configs
func populateUnusedKeyPositions(config *Config, dataMap map[string]interface{}) {
	// Detect unknown keys at top level
	knownFields := getKnownFields(reflect.TypeOf(Config{}), "json", "yaml")
	for key := range dataMap {
		if key == "jwt_svids" {
			// Handle jwt_svids separately
			continue
		}
		if !knownFields[key] {
			if config.UnusedKeyPositions == nil {
				config.UnusedKeyPositions = make(map[string][]token.Pos)
			}
			config.UnusedKeyPositions[key] = []token.Pos{}
		}
	}

	// Detect unknown keys in jwt_svids
	if jwtSVIDsData, ok := dataMap["jwt_svids"].([]interface{}); ok {
		jwtKnownFields := getKnownFields(reflect.TypeOf(JWTConfig{}), "json", "yaml")
		for i, jwtSVIDData := range jwtSVIDsData {
			if i >= len(config.JWTSVIDs) {
				// Ensure the array is large enough
				continue
			}
			if jwtMap, ok := jwtSVIDData.(map[string]interface{}); ok {
				for key := range jwtMap {
					if !jwtKnownFields[key] {
						if config.JWTSVIDs[i].UnusedKeyPositions == nil {
							config.JWTSVIDs[i].UnusedKeyPositions = make(map[string][]token.Pos)
						}
						config.JWTSVIDs[i].UnusedKeyPositions[key] = []token.Pos{}
					}
				}
			}
		}
	}
}

// getKnownFields returns a map of known field names from a struct type based on JSON/YAML tags
func getKnownFields(typ reflect.Type, tagNames ...string) map[string]bool {
	knownFields := make(map[string]bool)
	for i := range typ.NumField() {
		field := typ.Field(i)
		// Skip fields with json:"-" or yaml:"-"
		skip := false
		for _, tagName := range tagNames {
			tag := field.Tag.Get(tagName)
			if tag == "-" {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Check all tag names for the field name
		for _, tagName := range tagNames {
			tag := field.Tag.Get(tagName)
			if tag != "" && tag != "-" {
				// Handle tag options like "omitempty"
				tagParts := strings.Split(tag, ",")
				fieldName := tagParts[0]
				if fieldName != "" {
					knownFields[fieldName] = true
				}
			}
		}
	}
	return knownFields
}

// ParseHCLConfigFile parses the given HCL file into a Config struct
func ParseHCLConfigFile(file string) (*Config, error) {
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

// ParseConfigFlagOverrides handles command line arguments that override config file settings
func (c *Config) ParseConfigFlagOverrides(daemonModeFlag bool, daemonModeFlagName string) {
	if isFlagPassed(daemonModeFlagName) {
		// If daemon mode is set by CLI this takes precedence
		c.DaemonMode = &daemonModeFlag
	} else if c.DaemonMode == nil {
		// If daemon mode is not set, then default to true
		daemonMode := true
		c.DaemonMode = &daemonMode
	}
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
		spireAgentAddress := os.Getenv("SPIRE_AGENT_ADDRESS")
		spiffeEndpointSocket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")

		switch {
		case spireAgentAddress != "" && spiffeEndpointSocket == "":
			log.Warn("SPIRE_AGENT_ADDRESS is deprecated and will be removed in 0.10.0. Use SPIFFE_ENDPOINT_SOCKET instead.")
			c.AgentAddress = spireAgentAddress
		case spireAgentAddress != "" && spiffeEndpointSocket != "":
			return errors.New("both SPIRE_AGENT_ADDRESS and SPIFFE_ENDPOINT_SOCKET set. Use SPIFFE_ENDPOINT_SOCKET only. Support for SPIRE_AGENT_ADDRESS is deprecated and will be removed in 0.10.0")
		case spireAgentAddress == "" && spiffeEndpointSocket != "":
			c.AgentAddress = spiffeEndpointSocket
		default:
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

// LogConfig logs the fully reconciled configuration at debug level.
// The configuration is formatted as key=value pairs separated by commas.
func (c *Config) LogConfig(log logrus.FieldLogger) {
	// Check if debug level is enabled
	if logger, ok := log.(*logrus.Logger); ok {
		if !logger.IsLevelEnabled(logrus.DebugLevel) {
			return
		}
	} else if entry, ok := log.(*logrus.Entry); ok {
		if !entry.Logger.IsLevelEnabled(logrus.DebugLevel) {
			return
		}
	}

	// Pre-allocate slice with estimated capacity (Config struct has ~20 fields)
	configPairs := make([]string, 0, 30)
	configValue := reflect.ValueOf(c).Elem()
	configType := configValue.Type()

	for i := range configType.NumField() {
		field := configType.Field(i)
		fieldValue := configValue.Field(i)

		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}

		// Skip fields with json:"-" tag
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		// Get field name from json tag or use field name
		fieldName := field.Name
		if jsonTag != "" && jsonTag != "-" {
			// Extract field name from json tag (handle options like "omitempty")
			jsonTagParts := strings.Split(jsonTag, ",")
			if jsonTagParts[0] != "" {
				fieldName = jsonTagParts[0]
			}
		}

		// Format the value based on its type
		var valueStr string
		switch fieldValue.Kind() {
		case reflect.String:
			valueStr = fieldValue.String()
		case reflect.Bool:
			valueStr = fmt.Sprintf("%t", fieldValue.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			valueStr = fmt.Sprintf("%d", fieldValue.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			valueStr = fmt.Sprintf("%d", fieldValue.Uint())
		case reflect.Ptr:
			if fieldValue.IsNil() {
				valueStr = "nil"
			} else {
				elemValue := fieldValue.Elem()
				switch elemValue.Kind() {
				case reflect.Bool:
					valueStr = fmt.Sprintf("%t", elemValue.Bool())
				default:
					valueStr = fmt.Sprintf("%v", elemValue.Interface())
				}
			}
		case reflect.Struct:
			// For nested structs (like health.Config), format as nested key=value pairs
			nestedPairs := formatStructValue(fieldValue, fieldName)
			configPairs = append(configPairs, nestedPairs...)
			continue
		case reflect.Slice:
			if fieldValue.IsNil() {
				valueStr = "[]"
			} else {
				// Check if it's a slice of structs
				if fieldValue.Len() > 0 && fieldValue.Index(0).Kind() == reflect.Struct {
					// For struct slices (like JWTSVIDs), add each struct's fields directly to configPairs
					for j := range fieldValue.Len() {
						itemValue := fieldValue.Index(j)
						itemPairs := formatStructValue(itemValue, fmt.Sprintf("%s[%d]", fieldName, j))
						configPairs = append(configPairs, itemPairs...)
					}
					continue
				}
				// For non-struct slices, format as [item1;item2;...]
				// Use semicolon as separator to avoid conflicts with comma-separated key=value pairs
				var items []string
				for j := range fieldValue.Len() {
					itemValue := fieldValue.Index(j)
					items = append(items, fmt.Sprintf("%v", itemValue.Interface()))
				}
				valueStr = "[" + strings.Join(items, ";") + "]"
			}
		default:
			valueStr = fmt.Sprintf("%v", fieldValue.Interface())
		}

		// Only add non-empty values (or explicitly set values like false, 0, etc.)
		configPairs = append(configPairs, fmt.Sprintf("%s=%s", fieldName, valueStr))
	}

	log.Debugf("Reconciled configuration: %s", strings.Join(configPairs, ","))
}

// formatStructValue formats a struct value as key=value pairs with a prefix
func formatStructValue(structValue reflect.Value, prefix string) []string {
	// Pre-allocate slice with estimated capacity (health.Config has ~4 fields)
	pairs := make([]string, 0, 10)
	structType := structValue.Type()

	for i := range structType.NumField() {
		field := structType.Field(i)
		fieldValue := structValue.Field(i)

		if !fieldValue.CanInterface() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		fieldName := field.Name
		if jsonTag != "" && jsonTag != "-" {
			jsonTagParts := strings.Split(jsonTag, ",")
			if jsonTagParts[0] != "" {
				fieldName = jsonTagParts[0]
			}
		}

		fullFieldName := prefix + "." + fieldName
		var valueStr string

		switch fieldValue.Kind() {
		case reflect.String:
			valueStr = fieldValue.String()
		case reflect.Bool:
			valueStr = fmt.Sprintf("%t", fieldValue.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			valueStr = fmt.Sprintf("%d", fieldValue.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			valueStr = fmt.Sprintf("%d", fieldValue.Uint())
		case reflect.Slice:
			if fieldValue.IsNil() {
				valueStr = "[]"
			} else {
				var items []string
				for j := range fieldValue.Len() {
					items = append(items, fmt.Sprintf("%v", fieldValue.Index(j).Interface()))
				}
				// Use semicolon as separator to avoid conflicts with comma-separated key=value pairs
				valueStr = "[" + strings.Join(items, ";") + "]"
			}
		default:
			valueStr = fmt.Sprintf("%v", fieldValue.Interface())
		}

		pairs = append(pairs, fmt.Sprintf("%s=%s", fullFieldName, valueStr))
	}

	return pairs
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

func ParseConfig(configFile string, configFormat string, daemonModeFlag bool, daemonModeFlagName string) (*Config, error) {
	helperConfig, err := ParseConfigFile(configFile, configFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", configFile, err)
	}
	helperConfig.ParseConfigFlagOverrides(daemonModeFlag, daemonModeFlagName)
	return helperConfig, nil
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
