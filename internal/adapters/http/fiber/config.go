package fiber

import (
	"go_auth/internal/adapters/http/fiber/fibererr"
	"go_auth/internal/adapters/shared"
	"os"
	"strconv"
)

const (
	module     = "Fiber"
	portKey    = "GA_PORT"
	appNameKey = "GO_APP_NAME"
)

type FiberConfig struct {
	appName string
	port    uint16
}

func NewFiberConfig() (*FiberConfig, error) {
	return loadFiberConfig(os.Getenv)
}

func loadFiberConfig(getenv func(string) string) (*FiberConfig, error) {
	// 1. App Name Validation
	appName := getenv(appNameKey)
	if appName == "" {
		// FIXED: Passing the KEY name, not the empty variable
		return nil, shared.NewMissingVarErr(module, appNameKey)
	}

	// 2. Port Presence Validation
	envPort := getenv(portKey)
	if envPort == "" {
		return nil, shared.NewMissingVarErr(module, portKey)
	}

	// 3. Type Conversion Validation
	p, err := strconv.Atoi(envPort)
	if err != nil {
		// If using a sub-package:
		// return nil, fibererr.NewParseErr(portKey, err)

		// If errors are in the same package (Recommended for simplicity):
		return nil, fibererr.NewParseErr(portKey, err)
	}

	// 4. Logic/Range Validation
	if p <= 0 || p > 65535 {
		return nil, fibererr.NewInvalidPortErr(portKey)
	}

	return &FiberConfig{
		appName: appName,
		port:    uint16(p),
	}, nil
}

func (c *FiberConfig) AppName() string { return c.appName }
func (c *FiberConfig) Port() uint16    { return c.port }
