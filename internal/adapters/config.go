package adapters

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// The prefix is centralized here for easy maintenance
const envPrefix = "GA_"

type Config struct {
	App            AppConfig
	HTTP           HTTPConfig
	JWT            JWTConfig
	Password       PasswordConfig
	PasswordPolicy PasswordPolicyConfig
	SessionPolicy  SessionPolicyConfig
	Database       DatabaseConfig
	Seed           SeedConfig
}

type PasswordPolicyConfig struct {
	MinLength      uint8
	MaxLength      uint8
	RequireUpper   bool
	RequireNumber  bool
	RequireSpecial bool
}

type SessionPolicyConfig struct {
	Lifetime  time.Duration
	MaxActive uint8
}

type AppConfig struct {
	Name     string
	Env      string
	Debug    bool
	LogLevel string
}

type SeedConfig struct {
	AdminEmail    string
	AdminPassword string
}

type HTTPConfig struct {
	Port string
}

type JWTConfig struct {
	Secret    string
	Issuer    string
	Audience  string
	AccessTTL time.Duration
}

type PasswordConfig struct {
	BcryptCost int
}

type DatabaseConfig struct {
	URL string
}

func Load() (*Config, error) {
	app, err := loadApp()
	if err != nil {
		return nil, err
	}

	http := loadHTTP() // Simple string assignment, no parse error possible

	jwt, err := loadJWT()
	if err != nil {
		return nil, err
	}

	pass, err := loadPassword()
	if err != nil {
		return nil, err
	}

	passwordPolicy, err := loadPasswordPolicy()
	if err != nil {
		return nil, err
	}

	sessionPolicy, err := loadSessionPolicy()
	if err != nil {
		return nil, err
	}

	db := loadDatabase()
	seed := loadSeed()

	return &Config{
		App:            app,
		HTTP:           http,
		JWT:            jwt,
		Password:       pass,
		PasswordPolicy: passwordPolicy,
		SessionPolicy:  sessionPolicy,
		Database:       db,
		Seed:           seed,
	}, nil
}

// --- Private Loaders ---

func loadApp() (AppConfig, error) {
	debugMode, err := strconv.ParseBool(getEnv("DEBUG", "false"))
	if err != nil {
		return AppConfig{}, fmt.Errorf("config: invalid GA_DEBUG: %w", err)
	}

	return AppConfig{
		Name:     getEnv("APP_NAME", "GoAuthService"),
		Env:      getEnv("APP_ENV", "development"),
		Debug:    debugMode,
		LogLevel: getEnv("LOG_LEVEL", "info"),
	}, nil
}

func loadHTTP() HTTPConfig {
	return HTTPConfig{
		Port: getEnv("HTTP_PORT", "8080"),
	}
}

func loadJWT() (JWTConfig, error) {
	ttl, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return JWTConfig{}, fmt.Errorf("config: invalid GA_JWT_ACCESS_TTL: %w", err)
	}
	return JWTConfig{
		Secret:    getRequiredEnv("JWT_SECRET"),
		Issuer:    getEnv("JWT_ISSUER", "go-auth-service"),
		Audience:  getEnv("JWT_AUDIENCE", "go-auth-client"),
		AccessTTL: ttl,
	}, nil
}

func loadPassword() (PasswordConfig, error) {
	cost, err := strconv.Atoi(getEnv("PASSWORD_BCRYPT_COST", "12"))
	if err != nil {
		return PasswordConfig{}, fmt.Errorf("config: invalid GA_PASSWORD_BCRYPT_COST: %w", err)
	}
	return PasswordConfig{BcryptCost: cost}, nil
}

func loadPasswordPolicy() (PasswordPolicyConfig, error) {
	min, err := strconv.ParseUint(getEnv("PASS_MIN_LEN", "8"), 10, 8)
	if err != nil {
		return PasswordPolicyConfig{}, fmt.Errorf("config: invalid GA_PASS_MIN_LEN: %w", err)
	}
	max, err := strconv.ParseUint(getEnv("PASS_MAX_LEN", "64"), 10, 8)
	if err != nil {
		return PasswordPolicyConfig{}, fmt.Errorf("config: invalid GA_PASS_MAX_LEN: %w", err)
	}

	upper, err := strconv.ParseBool(getEnv("PASS_REQ_UPPER", "true"))
	if err != nil {
		return PasswordPolicyConfig{}, fmt.Errorf("config: invalid GA_PASS_REQ_UPPER: %w", err)
	}

	num, err := strconv.ParseBool(getEnv("PASS_REQ_NUM", "true"))
	if err != nil {
		return PasswordPolicyConfig{}, fmt.Errorf("config: invalid GA_PASS_REQ_NUM: %w", err)
	}

	spec, err := strconv.ParseBool(getEnv("PASS_REQ_SPECIAL", "true"))
	if err != nil {
		return PasswordPolicyConfig{}, fmt.Errorf("config: invalid GA_PASS_REQ_SPECIAL: %w", err)
	}

	return PasswordPolicyConfig{
		MinLength:      uint8(min),
		MaxLength:      uint8(max),
		RequireUpper:   upper,
		RequireNumber:  num,
		RequireSpecial: spec,
	}, nil
}

func loadSessionPolicy() (SessionPolicyConfig, error) {
	life, err := time.ParseDuration(getEnv("SESSION_LIFETIME", "24h"))
	if err != nil {
		return SessionPolicyConfig{}, fmt.Errorf("config: invalid GA_SESSION_LIFETIME: %w", err)
	}
	max, err := strconv.ParseUint(getEnv("SESSION_MAX_ACTIVE", "5"), 10, 8)
	if err != nil {
		return SessionPolicyConfig{}, fmt.Errorf("config: invalid GA_SESSION_MAX_ACTIVE: %w", err)
	}

	return SessionPolicyConfig{
		Lifetime:  life,
		MaxActive: uint8(max),
	}, nil
}

func loadDatabase() DatabaseConfig {
	return DatabaseConfig{
		URL: getRequiredEnv("DATABASE_URL"),
	}
}

func loadSeed() SeedConfig {
	return SeedConfig{
		AdminEmail:    getRequiredEnv("ADMIN_EMAIL"),
		AdminPassword: getRequiredEnv("ADMIN_PASSWORD"),
	}
}

// --- Helpers ---

func getEnv(key, defaultValue string) string {
	fullKey := envPrefix + key
	if value, exists := os.LookupEnv(fullKey); exists {
		return value
	}
	return defaultValue
}

func getRequiredEnv(key string) string {
	fullKey := envPrefix + key
	value := os.Getenv(fullKey)
	if value == "" {
		panic(fmt.Sprintf("config: environment variable %s is required", fullKey))
	}
	return value
}
