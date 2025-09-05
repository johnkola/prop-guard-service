package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server    ServerConfig
	Badger    BadgerConfig
	JWT       JWTConfig
	Vault     VaultConfig
	Bootstrap BootstrapConfig
}

type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type BadgerConfig struct {
	Dir                string
	ValueLogFileSize   int64
	MemTableSize       int64
	BlockCacheSize     int64
	IndexCacheSize     int64
	NumVersionsToKeep  int
	NumLevelZeroTables int
	Compression        bool
	EncryptionEnabled  bool
}

type JWTConfig struct {
	Secret      string
	ExpiryHours int
}

type VaultConfig struct {
	MasterKey          string
	AuditRetentionDays int
}

type BootstrapConfig struct {
	AdminUsername      string
	AdminPassword      string
	AdminEmail         string
	SkipPasswordPrompt bool
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
		Badger: BadgerConfig{
			Dir:                getEnv("BADGER_DIR", "./data/badger"),
			ValueLogFileSize:   getInt64Env("BADGER_VALUE_LOG_FILE_SIZE", 1<<28), // 256MB
			MemTableSize:       getInt64Env("BADGER_MEM_TABLE_SIZE", 64<<20),     // 64MB
			BlockCacheSize:     getInt64Env("BADGER_BLOCK_CACHE_SIZE", 256<<20),  // 256MB
			IndexCacheSize:     getInt64Env("BADGER_INDEX_CACHE_SIZE", 100<<20),  // 100MB
			NumVersionsToKeep:  getIntEnv("BADGER_NUM_VERSIONS_TO_KEEP", 1),
			NumLevelZeroTables: getIntEnv("BADGER_NUM_LEVEL_ZERO_TABLES", 5),
			Compression:        getBoolEnv("BADGER_COMPRESSION", true),
			EncryptionEnabled:  getBoolEnv("BADGER_ENCRYPTION", false),
		},
		JWT: JWTConfig{
			Secret:      getEnv("JWT_SECRET", ""),
			ExpiryHours: getIntEnv("JWT_EXPIRY_HOURS", 24),
		},
		Vault: VaultConfig{
			MasterKey:          getEnv("VAULT_MASTER_KEY", ""),
			AuditRetentionDays: getIntEnv("AUDIT_RETENTION_DAYS", 90),
		},
		Bootstrap: BootstrapConfig{
			AdminUsername:      getEnv("PROPGUARD_ADMIN_USERNAME", "admin"),
			AdminPassword:      getEnv("PROPGUARD_ADMIN_PASSWORD", "admin123"),
			AdminEmail:         getEnv("PROPGUARD_ADMIN_EMAIL", "admin@propguard.local"),
			SkipPasswordPrompt: getBoolEnv("PROPGUARD_SKIP_PASSWORD_PROMPT", false),
		},
	}

	// Validate required configurations
	if config.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	if config.Vault.MasterKey == "" {
		return nil, fmt.Errorf("VAULT_MASTER_KEY is required")
	}

	// Ensure master key is 32 bytes for AES-256
	if len(config.Vault.MasterKey) != 32 {
		return nil, fmt.Errorf("VAULT_MASTER_KEY must be exactly 32 bytes for AES-256")
	}

	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
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
