package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
)

type FiberConfig struct {
	AppName  string
	Port     uint16
	Debug    bool
	LogLevel slog.Level
}

func loadFiberConfig() (*FiberConfig, error) {
	appName := os.Getenv("GA_APP_NAME")
	if appName == "" {
		return nil, errors.New("fiber config error: GA_APP_NAME is required")
	}

	portStr := os.Getenv("GA_PORT")
	if portStr == "" {
		return nil, errors.New("fiber config error: GA_PORT is required")
	}

	portInt, err := strconv.Atoi(portStr)
	if err != nil || portInt <= 0 || portInt > 65535 {
		return nil, fmt.Errorf("fiber config error: GA_PORT must be a valid number between 1 and 65535: %w", err)
	}

	var debug bool
	debugStr := os.Getenv("GA_DEBUG")
	if debugStr != "" {
		debug, err = strconv.ParseBool(debugStr)
		if err != nil {
			return nil, fmt.Errorf("fiber config error: GA_DEBUG must be a valid boolean: %w", err)
		}
	} else {
		debug = false
	}

	var logLevel slog.Level
	if debug {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}

	return &FiberConfig{
		AppName:  appName,
		Port:     uint16(portInt),
		Debug:    debug,
		LogLevel: logLevel,
	}, nil
}

func (c *FiberConfig) ListenAddr() string { return fmt.Sprintf(":%d", c.Port) }
