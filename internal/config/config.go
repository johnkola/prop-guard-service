package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server ServerConfig
	Redis  RedisConfig
	JWT    JWTConfig
	Vault  VaultConfig
}

type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type RedisConfig struct {
	Host               string
	Port               string
	Password           string
	Database           int
	MaxRetries         int
	PoolSize           int
	MinIdleConns       int
	DialTimeout        time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	PoolTimeout        time.Duration
	IdleTimeout        time.Duration
	IdleCheckFrequency time.Duration
	MaxConnAge         time.Duration
	TLSEnabled         bool
	PersistenceEnabled bool
	AOFEnabled         bool
	RDBEnabled         bool
	RDBSaveInterval    time.Duration
	ClusterEnabled     bool
	ClusterNodes       []string
	MasterName         string
	SentinelAddresses  []string
}

type JWTConfig struct {
	Secret      string
	ExpiryHours int
}

type VaultConfig struct {
	MasterKey          string
	AuditRetentionDays int
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	config := &Config{
		Server: ServerConfig{
			Port:         getEnv("SERVER_PORT", "8080"),
			ReadTimeout:  getDurationEnv("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout: getDurationEnv("SERVER_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:  getDurationEnv("SERVER_IDLE_TIMEOUT", 60*time.Second),
		},
		Redis: RedisConfig{
			Host:               getEnv("REDIS_HOST", "localhost"),
			Port:               getEnv("REDIS_PORT", "6379"),
			Password:           getEnv("REDIS_PASSWORD", ""),
			Database:           getIntEnv("REDIS_DATABASE", 0),
			MaxRetries:         getIntEnv("REDIS_MAX_RETRIES", 3),
			PoolSize:           getIntEnv("REDIS_POOL_SIZE", 10),
			MinIdleConns:       getIntEnv("REDIS_MIN_IDLE_CONNS", 5),
			DialTimeout:        getDurationEnv("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:        getDurationEnv("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout:       getDurationEnv("REDIS_WRITE_TIMEOUT", 3*time.Second),
			PoolTimeout:        getDurationEnv("REDIS_POOL_TIMEOUT", 4*time.Second),
			IdleTimeout:        getDurationEnv("REDIS_IDLE_TIMEOUT", 5*time.Minute),
			IdleCheckFrequency: getDurationEnv("REDIS_IDLE_CHECK_FREQUENCY", 1*time.Minute),
			MaxConnAge:         getDurationEnv("REDIS_MAX_CONN_AGE", 30*time.Minute),
			TLSEnabled:         getBoolEnv("REDIS_TLS_ENABLED", false),
			PersistenceEnabled: getBoolEnv("REDIS_PERSISTENCE_ENABLED", true),
			AOFEnabled:         getBoolEnv("REDIS_AOF_ENABLED", true),
			RDBEnabled:         getBoolEnv("REDIS_RDB_ENABLED", true),
			RDBSaveInterval:    getDurationEnv("REDIS_RDB_SAVE_INTERVAL", 300*time.Second),
			ClusterEnabled:     getBoolEnv("REDIS_CLUSTER_ENABLED", false),
			ClusterNodes:       getStringSliceEnv("REDIS_CLUSTER_NODES", []string{}),
			MasterName:         getEnv("REDIS_MASTER_NAME", ""),
			SentinelAddresses:  getStringSliceEnv("REDIS_SENTINEL_ADDRESSES", []string{}),
		},
		JWT: JWTConfig{
			Secret:      getEnv("JWT_SECRET", "change-this-secret-in-production"),
			ExpiryHours: getIntEnv("JWT_EXPIRY_HOURS", 24),
		},
		Vault: VaultConfig{
			MasterKey:          getEnv("VAULT_MASTER_KEY", "default-master-key-change-in-production"),
			AuditRetentionDays: getIntEnv("AUDIT_RETENTION_DAYS", 90),
		},
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.JWT.Secret == "change-this-secret-in-production" {
		fmt.Println("WARNING: Using default JWT secret. Please set JWT_SECRET environment variable in production.")
	}

	if c.Vault.MasterKey == "default-master-key-change-in-production" {
		fmt.Println("WARNING: Using default master key. Please set VAULT_MASTER_KEY environment variable in production.")
	}

	if c.Redis.Host == "" {
		return fmt.Errorf("REDIS_HOST is required")
	}

	if c.Redis.Port == "" {
		return fmt.Errorf("REDIS_PORT is required")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma and trim spaces
		parts := make([]string, 0)
		for _, part := range split(value, ",") {
			trimmed := trim(part)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
		if len(parts) > 0 {
			return parts
		}
	}
	return defaultValue
}

// Helper functions for string manipulation
func split(s, sep string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i < len(s)-len(sep)+1 && s[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trim(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	// Trim trailing whitespace
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}
