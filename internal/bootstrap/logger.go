package bootstrap

import (
	"log/slog"
	"os"
)

func initLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}
