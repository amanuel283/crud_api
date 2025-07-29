package config

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"

	customlogger "github.com/izymalhaw/go-crud/yishakterefe/internal/core/logger"
)

var (
	ErrInvalidPort  = errors.New("port number is invalid")
	ErrLogLevel     = errors.New("log level not set")
	ErrInvalidLevel = errors.New("invalid log level")
	ErrInvalidEnv   = errors.New("env not set or invalid")
	ErrDatabaseURL  = errors.New("database URL not set")
)


var Environment = map[string]string{
	"dev":  "development",
	"prod": "production",
}

type Config struct {
	Port           int
	LogLevel       slog.Level
	Env            string
	DatabaseURL    string
	DBMaxOpenConns int
	DBMaxIdleConns int
	DBMaxLifetime  time.Duration
	JWTSecret      string
}


func NewConfig() (*Config, error) {
	cfg := &Config{}
	if err := cfg.loadEnv(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) loadEnv() error {
	// Load environment variables from .env file
	env := os.Getenv("ENV")
	if env == "" {
		return ErrInvalidEnv
	}

	evalue, ok := Environment[env]
	if !ok {
		return ErrInvalidEnv
	}
	c.Env = evalue

	// Set log level based on environment variable
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		return ErrLogLevel
	}

	lvl, ok := customlogger.LogLevels[logLevel]
	if !ok {
		return ErrInvalidLevel
	}
	c.LogLevel = lvl

	// Set port from environment variable
	portStr := os.Getenv("PORT")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ErrInvalidPort
	}
	c.Port = port

	// Database configuration
	c.DatabaseURL = os.Getenv("DATABASE_URL")
	if c.DatabaseURL == "" && c.Env != "test" {
		return ErrDatabaseURL
	}

	// Connection pool settings with defaults
	c.DBMaxOpenConns = 25
	if maxOpen := os.Getenv("DB_MAX_OPEN_CONNS"); maxOpen != "" {
		if val, err := strconv.Atoi(maxOpen); err == nil {
			c.DBMaxOpenConns = val
		}
	}

	c.DBMaxIdleConns = 25
	if maxIdle := os.Getenv("DB_MAX_IDLE_CONNS"); maxIdle != "" {
		if val, err := strconv.Atoi(maxIdle); err == nil {
			c.DBMaxIdleConns = val
		}
	}

	c.DBMaxLifetime = 5 * time.Minute
	if maxLife := os.Getenv("DB_MAX_LIFETIME"); maxLife != "" {
		if val, err := time.ParseDuration(maxLife); err == nil {
			c.DBMaxLifetime = val
		}
	}

	// ✅ Fix JWT_SECRET logic before return
	c.JWTSecret = os.Getenv("JWT_SECRET")
	if c.JWTSecret == "" {
		return errors.New("JWT_SECRET not set")
	}

	return nil
}
