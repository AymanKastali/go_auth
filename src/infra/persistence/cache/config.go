package cache

import (
	"os"
	"strconv"
)

type RedisConfig struct {
	RedisAddr string
	RedisPass string
	RedisDB   int
}

func Load() *RedisConfig {
	return &RedisConfig{
		RedisAddr: getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPass: getEnv("REDIS_PASSWORD", ""),
		RedisDB:   getEnvInt("REDIS_DB", 0),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}

	// Convert string to int
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return fallback
	}
	return val
}
