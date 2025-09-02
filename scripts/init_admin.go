package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bazarbozorg/PropGuard/internal/config"
	"github.com/bazarbozorg/PropGuard/internal/entity"
	"github.com/bazarbozorg/PropGuard/internal/repository"
	"github.com/bazarbozorg/PropGuard/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Connect to MongoDB
	mongodb, err := repository.NewMongoDB(cfg.Database.URI, cfg.Database.Database)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		mongodb.Disconnect(ctx)
	}()

	// Create indexes
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mongodb.CreateIndexes(ctx); err != nil {
		log.Printf("Warning: Failed to create indexes: %v", err)
	}

	// Initialize repository
	userRepo := repository.NewUserRepository(mongodb)

	// Check if admin user already exists
	existingUser, err := userRepo.FindByUsername(ctx, "admin")
	if err == nil && existingUser != nil {
		fmt.Println("Admin user already exists")
		return
	}

	// Create admin user with configurable password
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		log.Fatalf("ADMIN_PASSWORD environment variable must be set")
	}
	if len(password) < 8 {
		log.Fatalf("ADMIN_PASSWORD must be at least 8 characters long")
	}
	hashedPassword, err := service.HashPassword(password)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	adminUser := entity.NewVaultUser("admin", hashedPassword)
	adminUser.Roles = []entity.VaultRole{entity.RoleRoot, entity.RoleAdmin}

	if err := userRepo.Create(ctx, adminUser); err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}

	fmt.Printf("Admin user created successfully!\n")
	fmt.Printf("Username: admin\n")
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("WARNING: Change the default password after first login!\n")
}
