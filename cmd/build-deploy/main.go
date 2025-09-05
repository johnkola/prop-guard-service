package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

func main() {
	fmt.Printf("%s🚀 Building and deploying PropGuard...%s\n", ColorBlue, ColorReset)

	// Step 1: Generate Swagger documentation
	fmt.Printf("%s📚 Generating Swagger documentation...%s\n", ColorCyan, ColorReset)
	if err := generateSwaggerDocs(); err != nil {
		fmt.Printf("%s⚠️  Swagger generation failed: %v, continuing with build...%s\n", ColorYellow, err, ColorReset)
	} else {
		fmt.Printf("%s✅ Swagger documentation generated successfully!%s\n", ColorGreen, ColorReset)
	}

	// Step 2: Build and deploy with Docker Compose
	fmt.Printf("%s🐳 Building images and deploying services...%s\n", ColorBlue, ColorReset)
	if err := dockerComposeBuild(); err != nil {
		fmt.Printf("%s❌ Docker build failed: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	// Step 3: Check service status
	fmt.Printf("%s🔍 Checking service status...%s\n", ColorCyan, ColorReset)
	time.Sleep(5 * time.Second)
	if err := checkServiceStatus(); err != nil {
		fmt.Printf("%s⚠️  Service status check failed: %v%s\n", ColorYellow, err, ColorReset)
	}

	fmt.Printf("%s✅ Build and deploy completed!%s\n", ColorGreen, ColorReset)
	fmt.Println()
	fmt.Printf("%s🌐 Services available at:%s\n", ColorPurple, ColorReset)
	fmt.Println("   - Backend API: http://localhost:8080")
	fmt.Println("   - Swagger Docs: http://localhost:8080/swagger/index.html")
	fmt.Println("   - Frontend: http://localhost:3000")
}

func generateSwaggerDocs() error {
	// Check if swag command exists
	if !commandExists("swag") {
		return fmt.Errorf("swag command not found")
	}

	cmd := exec.Command("swag", "init", "-g", "cmd/server/main.go", "-o", "docs/", "--parseDependency", "--parseInternal")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func dockerComposeBuild() error {
	cmd := exec.Command("docker-compose", "up", "--build", "-d")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func checkServiceStatus() error {
	cmd := exec.Command("docker-compose", "ps")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

func commandExists(command string) bool {
	cmd := exec.Command("which", command)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// Additional utility functions for more advanced build operations

func BuildInfo() map[string]interface{} {
	pwd, _ := os.Getwd()
	return map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"directory":  pwd,
		"go_version": getGoVersion(),
		"git_commit": getGitCommit(),
		"git_branch": getGitBranch(),
	}
}

func getGoVersion() string {
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getGitCommit() string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getGitBranch() string {
	cmd := exec.Command("git", "branch", "--show-current")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// Advanced build functions

func CleanBuild() error {
	fmt.Printf("%s🧹 Cleaning previous builds...%s\n", ColorYellow, ColorReset)

	// Remove old binaries
	if err := os.RemoveAll("bin/"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clean bin directory: %w", err)
	}

	// Docker cleanup
	cmd := exec.Command("docker", "system", "prune", "-f")
	if err := cmd.Run(); err != nil {
		fmt.Printf("%s⚠️  Docker cleanup failed: %v%s\n", ColorYellow, err, ColorReset)
	}

	return nil
}

func BuildBinary() error {
	fmt.Printf("%s🔨 Building PropGuard binary...%s\n", ColorBlue, ColorReset)

	// Ensure bin directory exists
	if err := os.MkdirAll("bin", 0755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}

	// Build the binary
	cmd := exec.Command("go", "build", "-o", "bin/propguard", "cmd/server/main.go")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func TestBeforeBuild() error {
	fmt.Printf("%s🧪 Running tests...%s\n", ColorCyan, ColorReset)

	cmd := exec.Command("go", "test", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func LintCode() error {
	fmt.Printf("%s📝 Linting code...%s\n", ColorCyan, ColorReset)

	if !commandExists("golangci-lint") {
		fmt.Printf("%s⚠️  golangci-lint not found, skipping lint%s\n", ColorYellow, ColorReset)
		return nil
	}

	cmd := exec.Command("golangci-lint", "run")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Extended build with all steps
func FullBuild() error {
	steps := []struct {
		name string
		fn   func() error
	}{
		{"Clean", CleanBuild},
		{"Test", TestBeforeBuild},
		{"Lint", LintCode},
		{"Generate Docs", generateSwaggerDocs},
		{"Build Binary", BuildBinary},
		{"Docker Build", dockerComposeBuild},
		{"Status Check", checkServiceStatus},
	}

	for _, step := range steps {
		fmt.Printf("%s▶️  %s...%s\n", ColorBlue, step.name, ColorReset)
		if err := step.fn(); err != nil {
			fmt.Printf("%s❌ %s failed: %v%s\n", ColorRed, step.name, err, ColorReset)
			return err
		}
		fmt.Printf("%s✅ %s completed%s\n", ColorGreen, step.name, ColorReset)
	}

	return nil
}

// Development mode with file watching (if you want to extend this)
func DevMode() error {
	fmt.Printf("%s🛠️  Starting development mode...%s\n", ColorBlue, ColorReset)

	cmd := exec.Command("docker-compose", "up", "--build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Environment-specific builds
func BuildForEnvironment(env string) error {
	fmt.Printf("%s🏗️  Building for environment: %s%s\n", ColorBlue, env, ColorReset)

	envFile := filepath.Join(".env." + env)
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return fmt.Errorf("environment file %s not found", envFile)
	}

	// Copy environment file
	cmd := exec.Command("cp", envFile, ".env")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy environment file: %w", err)
	}

	return dockerComposeBuild()
}
