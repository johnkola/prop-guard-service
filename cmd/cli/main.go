package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"PropGuard/internal/config"
	"PropGuard/internal/repository"
	"PropGuard/internal/service"

	"github.com/spf13/cobra"
)

var (
	configPath string
	badgerDir  string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "propguard-cli",
		Short: "PropGuard CLI - Administration tool for PropGuard secrets management",
		Long: `PropGuard CLI is a command-line administration tool for PropGuard,
a secure secrets management and configuration service.

Use this CLI to bootstrap the system, manage users, and perform administrative tasks.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "config file path")
	rootCmd.PersistentFlags().StringVar(&badgerDir, "badger-dir", "/app/data", "BadgerDB data directory")

	// Add commands
	rootCmd.AddCommand(bootstrapCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(systemCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("PropGuard CLI v1.0.0-beta")
		fmt.Println("Built for PropGuard secrets management system")
	},
}

// Bootstrap command
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Initialize PropGuard system",
	Long: `Bootstrap command initializes the PropGuard system by:
- Creating default admin role with full permissions
- Creating initial admin user (admin/admin123)
- Setting up system configuration
- Marking system as bootstrapped

This command should be run once when setting up PropGuard for the first time.`,
	Run: runBootstrap,
}

func runBootstrap(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	fmt.Println("🚀 PropGuard CLI - System Bootstrap")
	fmt.Println("===================================")

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize BadgerDB
	badgerClient, err := initializeBadger(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize BadgerDB: %v", err)
	}
	defer badgerClient.Close()

	// Create bootstrap service
	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)

	// Check if already bootstrapped
	isFirstRun, err := bootstrapService.IsFirstRun(ctx)
	if err != nil {
		log.Fatalf("Failed to check bootstrap status: %v", err)
	}

	if !isFirstRun {
		fmt.Println("✅ System is already bootstrapped!")
		fmt.Println("If you need to re-bootstrap, please remove the BadgerDB data directory first.")
		return
	}

	fmt.Println("📋 Starting bootstrap process...")

	// Run bootstrap
	if err := bootstrapService.RunBootstrap(ctx); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}

	fmt.Println("🎉 Bootstrap completed successfully!")
	fmt.Println()
	fmt.Println("Default Admin Credentials:")
	fmt.Println("  Username: admin")
	fmt.Println("  Password: admin123")
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Change the admin password after first login!")
	fmt.Println("🌐 Access the web interface at: http://localhost:8080")
	fmt.Println("📚 API documentation at: http://localhost:8080/swagger/index.html")
}

// System command group
var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System administration commands",
	Long:  `System administration commands for PropGuard maintenance and diagnostics.`,
}

func init() {
	systemCmd.AddCommand(systemStatusCmd)
	systemCmd.AddCommand(systemStatsCmd)
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check system status",
	Long:  `Check the health and status of PropGuard system components.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		fmt.Println("🔍 PropGuard System Status")
		fmt.Println("=========================")

		// Load configuration
		cfg, err := loadConfig()
		if err != nil {
			fmt.Printf("❌ Configuration: Failed to load (%v)\n", err)
			return
		}
		fmt.Println("✅ Configuration: Loaded successfully")

		// Check BadgerDB
		badgerClient, err := initializeBadger(cfg)
		if err != nil {
			fmt.Printf("❌ Database: Connection failed (%v)\n", err)
			return
		}
		defer badgerClient.Close()

		if err := badgerClient.Ping(); err != nil {
			fmt.Printf("❌ Database: Health check failed (%v)\n", err)
			return
		}
		fmt.Println("✅ Database: BadgerDB operational")

		// Check bootstrap status
		bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
		isFirstRun, err := bootstrapService.IsFirstRun(ctx)
		if err != nil {
			fmt.Printf("⚠️  Bootstrap: Status check failed (%v)\n", err)
		} else if isFirstRun {
			fmt.Println("⚠️  Bootstrap: System not initialized (run 'propguard-cli bootstrap')")
		} else {
			fmt.Println("✅ Bootstrap: System initialized")
		}

		fmt.Println("✅ System Status: Operational")
	},
}

var systemStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show system statistics",
	Long:  `Display system statistics including database size, user count, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("📊 PropGuard System Statistics")
		fmt.Println("=============================")

		// Load configuration
		cfg, err := loadConfig()
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}

		// Initialize BadgerDB
		badgerClient, err := initializeBadger(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize BadgerDB: %v", err)
		}
		defer badgerClient.Close()

		// Get database stats
		stats := badgerClient.GetStats()
		fmt.Printf("Database Size (LSM): %d bytes\n", stats["lsm_size"])
		fmt.Printf("Database Size (Value Log): %d bytes\n", stats["vlog_size"])
		fmt.Printf("Approximate Key Count: %d\n", stats["num_keys"])
		fmt.Printf("Number of Tables: %s\n", stats["num_tables"])
	},
}

// User command group
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management commands",
	Long:  `User management commands for creating, updating, and managing PropGuard users.`,
}

func init() {
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userResetPasswordCmd)
}

var userCreateCmd = &cobra.Command{
	Use:   "create [username] [email]",
	Short: "Create a new user",
	Long:  `Create a new PropGuard user with specified username and email.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		email := args[1]

		fmt.Printf("👤 Creating user: %s (%s)\n", username, email)
		fmt.Println("⚠️  User creation via CLI is not yet implemented.")
		fmt.Println("Please use the web interface or API to create users.")
		fmt.Println("🌐 Web interface: http://localhost:8080")
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Long:  `List all PropGuard users in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("👥 PropGuard Users")
		fmt.Println("=================")
		fmt.Println("⚠️  User listing via CLI is not yet implemented.")
		fmt.Println("Please use the web interface or API to list users.")
		fmt.Println("🌐 Web interface: http://localhost:8080")
	},
}

var userResetPasswordCmd = &cobra.Command{
	Use:   "reset-password [username]",
	Short: "Reset user password",
	Long:  `Reset a user's password to a temporary password.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]

		fmt.Printf("🔑 Resetting password for user: %s\n", username)
		fmt.Println("⚠️  Password reset via CLI is not yet implemented.")
		fmt.Println("Please use the web interface or API to reset passwords.")
		fmt.Println("🌐 Web interface: http://localhost:8080")
	},
}

// Helper functions
func loadConfig() (*config.Config, error) {
	// For now, just use the standard Load() function
	// TODO: Add support for custom config files if needed
	return config.Load()
}

func initializeBadger(cfg *config.Config) (*repository.BadgerClient, error) {
	// Use command-line badger-dir if provided, otherwise use config
	dataDir := badgerDir
	if dataDir == "/app/data" && cfg.Badger.Dir != "" {
		dataDir = cfg.Badger.Dir
	}

	badgerConfig := repository.BadgerConfig{
		Dir:                dataDir,
		ValueLogFileSize:   cfg.Badger.ValueLogFileSize,
		MemTableSize:       cfg.Badger.MemTableSize,
		BlockCacheSize:     cfg.Badger.BlockCacheSize,
		IndexCacheSize:     cfg.Badger.IndexCacheSize,
		NumVersionsToKeep:  cfg.Badger.NumVersionsToKeep,
		NumLevelZeroTables: cfg.Badger.NumLevelZeroTables,
		Compression:        cfg.Badger.Compression,
	}

	// Add encryption key if encryption is enabled
	if cfg.Badger.EncryptionEnabled {
		badgerConfig.EncryptionKey = []byte(cfg.Vault.MasterKey)
	}

	return repository.NewBadgerClient(badgerConfig)
}
