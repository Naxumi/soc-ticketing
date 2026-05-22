package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	JWT      JWTConfig
}

type AppConfig struct {
	Port             int
	Env              string
	WebhookAPIKey    string
	AnalyzeAPIURL    string
	AnalyzeModelsURL string
	AnalyzeAPIKey    string
	AnalyzeTimeout   time.Duration
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
}

type JWTConfig struct {
	Secret         string
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	Issuer         string
	AccessAudience string
}

func Load() (*Config, error) {
	// Optional; don't hard-fail if .env is not present.
	_ = godotenv.Load()

	appPort, err := strconv.Atoi(getEnv("APP_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid APP_PORT: %w", err)
	}

	analyzeTimeout, err := time.ParseDuration(getEnv("ANALYZE_API_TIMEOUT", "60s"))
	if err != nil {
		return nil, fmt.Errorf("invalid ANALYZE_API_TIMEOUT: %w", err)
	}

	dbPort, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "1h"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_ACCESS_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "168h"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_REFRESH_TTL: %w", err)
	}

	cfg := &Config{
		App: AppConfig{
			Port:             appPort,
			Env:              getEnv("APP_ENV", "development"),
			WebhookAPIKey:    getEnv("WEBHOOK_API_KEY", ""),
			AnalyzeAPIURL:    getEnv("ANALYZE_API_URL", ""),
			AnalyzeModelsURL: getEnv("ANALYZE_MODELS_URL", ""),
			AnalyzeAPIKey:    getEnv("ANALYZE_API_KEY", ""),
			AnalyzeTimeout:   analyzeTimeout,
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     dbPort,
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", "soc_ticketing"),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		},
		JWT: JWTConfig{
			Secret:         os.Getenv("JWT_SECRET"),
			AccessTTL:      accessTTL,
			RefreshTTL:     refreshTTL,
			Issuer:         getEnv("JWT_ISSUER", "dashboard-soc"),
			AccessAudience: getEnv("JWT_AUD", "dashboard-soc"),
		},
	}

	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}
