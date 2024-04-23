package main

func validateOSConfig(c *Config) error {
	if c.RenewSignal != "" {
		return errors.New("sending signals is not supported on windows")
	}
	return nil
}
