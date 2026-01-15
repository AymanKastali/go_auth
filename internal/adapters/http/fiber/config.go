package fiber

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

type FiberConfig struct {
	appName string
	port    uint16
}

// NewFiberConfig loads and validates Fiber settings from environment variables.
func NewFiberConfig() (*FiberConfig, error) {
	cfg := &FiberConfig{}

	// 1. App Name Validation
	cfg.appName = os.Getenv("GA_APP_NAME")
	if cfg.appName == "" {
		return nil, errors.New("fiber config error: GA_APP_NAME is required")
	}

	// 2. Port Presence Validation
	portStr := os.Getenv("GA_PORT")
	if portStr == "" {
		return nil, errors.New("fiber config error: GA_PORT is required")
	}

	// 3. Type Conversion Validation
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("fiber config error: GA_PORT must be a valid number: %w", err)
	}

	// 4. Logic/Range Validation (0-65535)
	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("fiber config error: GA_PORT %d is out of valid range (1-65535)", p)
	}

	cfg.port = uint16(p)
	return cfg, nil
}

func (c *FiberConfig) AppName() string { return c.appName }
func (c *FiberConfig) Port() uint16    { return c.port }

// ListenAddr returns the formatted string for the Fiber Listen method (e.g., ":8080")
func (c *FiberConfig) ListenAddr() string { return fmt.Sprintf(":%d", c.port) }
