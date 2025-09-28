package disk

import (
	"io/fs"
)

type JWTConfig struct {
	Dir            string
	SVIDFileName   string
	SVIDFileMode   fs.FileMode
	BundleFileName string
	BundleFileMode fs.FileMode
}

type Config struct {
	X509 X509Config
	JWT  JWTConfig
	Hint string
}

type Disk struct {
	c Config
}

func New(c Config) *Disk {
	return &Disk{
		c: c,
	}
}
