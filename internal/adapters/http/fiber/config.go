package fiber

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
)

type FiberConfig struct {
	appName string
	port    uint16
	debug   bool
}

func NewFiberConfig() (*FiberConfig, error) {
	cfg := &FiberConfig{}

	cfg.appName = os.Getenv("GA_APP_NAME")
	if cfg.appName == "" {
		return nil, errors.New("fiber config error: GA_APP_NAME is required")
	}

	portStr := os.Getenv("GA_PORT")
	if portStr == "" {
		return nil, errors.New("fiber config error: GA_PORT is required")
	}

	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("fiber config error: GA_PORT must be a valid number: %w", err)
	}

	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("fiber config error: GA_PORT %d is out of valid range (1-65535)", p)
	}

	debugStr := os.Getenv("GA_DEBUG")
	if debugStr != "" {
		debug, err := strconv.ParseBool(debugStr)
		if err != nil {
			return nil, fmt.Errorf("fiber config error: GA_DEBUG must be a valid boolean: %w", err)
		}
		cfg.debug = debug
	} else {
		cfg.debug = false
	}

	cfg.port = uint16(p)
	return cfg, nil
}

func (c *FiberConfig) AppName() string { return c.appName }
func (c *FiberConfig) Port() uint16    { return c.port }
func (c *FiberConfig) Debug() bool     { return c.debug }

func (c *FiberConfig) LogLevel() slog.Level {
	switch c.debug {
	case true:
		return slog.LevelDebug
	case false:
		return slog.LevelInfo
	default:
		return slog.LevelInfo
	}
}

func (c *FiberConfig) ListenAddr() string { return fmt.Sprintf(":%d", c.port) }
