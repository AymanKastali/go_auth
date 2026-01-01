package fiber

import (
	"fmt"
	"os"
	"strconv"
)

type FiberConfig struct {
	appName string
	port    uint16
}

func NewFiberConfig() (*FiberConfig, error) {
	envPort := os.Getenv("APP_PORT")
	if envPort == "" {
		return nil, fmt.Errorf("APP_PORT environment variable is not set")
	}

	p, err := strconv.Atoi(envPort)
	if err != nil {
		return nil, fmt.Errorf("invalid APP_PORT value '%s': %w", envPort, err)
	}

	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("APP_PORT must be between 1 and 65535")
	}

	return &FiberConfig{
		appName: "GoAuthApp",
		port:    uint16(p),
	}, nil
}

func (c *FiberConfig) AppName() string {
	return c.appName
}

func (c *FiberConfig) Port() uint16 {
	return c.port
}
