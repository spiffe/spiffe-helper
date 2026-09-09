//go:build windows
// +build windows

package config

import "errors"

func validateOSConfig(c *Config) error {
	if c.Reload.Signal != "" {
		return errors.New("sending signals is not supported on windows")
	}
	return nil
}
