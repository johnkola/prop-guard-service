package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"PropGuard/internal/entity"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

// SecretGenerationService handles automatic secret generation based on policies
type SecretGenerationService interface {
	GenerateSecret(policy *entity.SecretPolicy, rules string) (map[string]interface{}, error)
	ValidateSecretFormat(policy *entity.SecretPolicy, value string) error
	ParseGenerationRules(rules string) (*GenerationConfig, error)
}

type GenerationConfig struct {
	// Password generation
	Length         int    `json:"length,omitempty"`
	IncludeUpper   bool   `json:"include_upper,omitempty"`
	IncludeLower   bool   `json:"include_lower,omitempty"`
	IncludeNumbers bool   `json:"include_numbers,omitempty"`
	IncludeSymbols bool   `json:"include_symbols,omitempty"`
	ExcludeChars   string `json:"exclude_chars,omitempty"`

	// Key generation
	KeySize   int    `json:"key_size,omitempty"`
	KeyType   string `json:"key_type,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	// Format validation
	Pattern string `json:"pattern,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Suffix  string `json:"suffix,omitempty"`

	// API Key generation
	APIKeyFormat string `json:"api_key_format,omitempty"`

	// JWT generation
	JWTIssuer    string            `json:"jwt_issuer,omitempty"`
	JWTClaims    map[string]string `json:"jwt_claims,omitempty"`
	JWTAlgorithm string            `json:"jwt_algorithm,omitempty"`
}

type secretGenerationService struct{}

func NewSecretGenerationService() SecretGenerationService {
	return &secretGenerationService{}
}

func (s *secretGenerationService) GenerateSecret(policy *entity.SecretPolicy, rules string) (map[string]interface{}, error) {
	config, err := s.ParseGenerationRules(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generation rules: %w", err)
	}

	switch policy.SecretType {
	case entity.SecretTypePassword:
		return s.generatePassword(config)
	case entity.SecretTypeAPIKey:
		return s.generateAPIKey(config)
	case entity.SecretTypeJWTSecret:
		return s.generateJWTSecret(config)
	case entity.SecretTypeRSAKeyPair:
		return s.generateRSAKeyPair(config)
	case entity.SecretTypeECKeyPair:
		return s.generateECKeyPair(config)
	case entity.SecretTypeAESKey:
		return s.generateAESKey(config)
	case entity.SecretTypeHMACKey:
		return s.generateHMACKey(config)
	case entity.SecretTypeDatabaseCred:
		return s.generateDatabaseCredentials(config)
	case entity.SecretTypeSSHKey:
		return s.generateSSHKeyPair(config)
	case entity.SecretTypeOAuthCredentials:
		return s.generateOAuthCredentials(config)
	default:
		return s.generateGenericSecret(config)
	}
}

func (s *secretGenerationService) ValidateSecretFormat(policy *entity.SecretPolicy, value string) error {
	if policy.RegenerationRules == "" {
		return nil // No validation rules defined
	}

	config, err := s.ParseGenerationRules(policy.RegenerationRules)
	if err != nil {
		return fmt.Errorf("failed to parse validation rules: %w", err)
	}

	// Pattern validation
	if config.Pattern != "" {
		matched, err := regexp.MatchString(config.Pattern, value)
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		if !matched {
			return fmt.Errorf("secret does not match required pattern: %s", config.Pattern)
		}
	}

	// Length validation for passwords
	if policy.SecretType == entity.SecretTypePassword && config.Length > 0 {
		if len(value) < config.Length {
			return fmt.Errorf("password length %d is below minimum %d", len(value), config.Length)
		}
	}

	// Prefix/suffix validation
	if config.Prefix != "" && !strings.HasPrefix(value, config.Prefix) {
		return fmt.Errorf("secret must start with prefix: %s", config.Prefix)
	}
	if config.Suffix != "" && !strings.HasSuffix(value, config.Suffix) {
		return fmt.Errorf("secret must end with suffix: %s", config.Suffix)
	}

	return nil
}

func (s *secretGenerationService) ParseGenerationRules(rules string) (*GenerationConfig, error) {
	if rules == "" {
		return s.getDefaultConfig(), nil
	}

	var config GenerationConfig
	if err := json.Unmarshal([]byte(rules), &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules JSON: %w", err)
	}

	// Apply defaults for missing fields
	defaultConfig := s.getDefaultConfig()
	if config.Length == 0 {
		config.Length = defaultConfig.Length
	}
	if config.KeySize == 0 {
		config.KeySize = defaultConfig.KeySize
	}

	return &config, nil
}

func (s *secretGenerationService) getDefaultConfig() *GenerationConfig {
	return &GenerationConfig{
		Length:         32,
		IncludeUpper:   true,
		IncludeLower:   true,
		IncludeNumbers: true,
		IncludeSymbols: true,
		KeySize:        2048,
		KeyType:        "rsa",
		Algorithm:      "RS256",
		APIKeyFormat:   "pgs_${random32}",
		JWTAlgorithm:   "HS256",
	}
}

// Generation methods for different secret types

func (s *secretGenerationService) generatePassword(config *GenerationConfig) (map[string]interface{}, error) {
	charset := ""
	if config.IncludeLower {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if config.IncludeUpper {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if config.IncludeNumbers {
		charset += "0123456789"
	}
	if config.IncludeSymbols {
		charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	// Remove excluded characters
	if config.ExcludeChars != "" {
		for _, char := range config.ExcludeChars {
			charset = strings.ReplaceAll(charset, string(char), "")
		}
	}

	if len(charset) == 0 {
		return nil, fmt.Errorf("no valid characters available for password generation")
	}

	password, err := s.generateRandomString(config.Length, charset)
	if err != nil {
		return nil, err
	}

	// Add prefix/suffix if specified
	if config.Prefix != "" {
		password = config.Prefix + password
	}
	if config.Suffix != "" {
		password = password + config.Suffix
	}

	return map[string]interface{}{
		"password": password,
		"length":   len(password),
	}, nil
}

func (s *secretGenerationService) generateAPIKey(config *GenerationConfig) (map[string]interface{}, error) {
	format := config.APIKeyFormat
	if format == "" {
		format = "pgs_${random32}"
	}

	// Replace placeholders
	random32, err := s.generateRandomString(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil {
		return nil, err
	}

	apiKey := strings.ReplaceAll(format, "${random32}", random32)

	return map[string]interface{}{
		"api_key": apiKey,
		"format":  format,
	}, nil
}

func (s *secretGenerationService) generateJWTSecret(config *GenerationConfig) (map[string]interface{}, error) {
	keyLength := config.Length
	if keyLength < 32 {
		keyLength = 64 // JWT secrets should be at least 256 bits
	}

	secret, err := s.generateRandomString(keyLength, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
	if err != nil {
		return nil, err
	}

	// Generate a sample JWT token for validation
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": config.JWTIssuer,
		"sub": "sample",
		"exp": 1234567890,
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to generate sample JWT: %w", err)
	}

	return map[string]interface{}{
		"secret":     secret,
		"algorithm":  config.JWTAlgorithm,
		"sample_jwt": tokenString,
		"length":     len(secret),
	}, nil
}

func (s *secretGenerationService) generateRSAKeyPair(config *GenerationConfig) (map[string]interface{}, error) {
	keySize := config.KeySize
	if keySize < 2048 {
		keySize = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// Encode public key
	publicKeyPKCS1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKCS1,
	}
	publicKeyStr := string(pem.EncodeToMemory(publicKeyPEM))

	return map[string]interface{}{
		"private_key": privateKeyStr,
		"public_key":  publicKeyStr,
		"key_size":    keySize,
		"algorithm":   "RSA",
	}, nil
}

func (s *secretGenerationService) generateECKeyPair(config *GenerationConfig) (map[string]interface{}, error) {
	// For simplicity, we'll generate ECDSA keys using Go's crypto/ecdsa
	// This is a placeholder - full implementation would use proper EC curve generation
	return map[string]interface{}{
		"message": "EC key pair generation not yet implemented",
		"type":    "ECDSA",
	}, nil
}

func (s *secretGenerationService) generateAESKey(config *GenerationConfig) (map[string]interface{}, error) {
	keySize := config.KeySize
	if keySize != 128 && keySize != 192 && keySize != 256 {
		keySize = 256 // Default to AES-256
	}

	keyBytes := keySize / 8
	key := make([]byte, keyBytes)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	return map[string]interface{}{
		"key":       base64.StdEncoding.EncodeToString(key),
		"key_hex":   fmt.Sprintf("%x", key),
		"key_size":  keySize,
		"algorithm": fmt.Sprintf("AES-%d", keySize),
	}, nil
}

func (s *secretGenerationService) generateHMACKey(config *GenerationConfig) (map[string]interface{}, error) {
	keyLength := config.Length
	if keyLength < 32 {
		keyLength = 64 // HMAC keys should be at least 256 bits
	}

	key := make([]byte, keyLength)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	return map[string]interface{}{
		"key":       base64.StdEncoding.EncodeToString(key),
		"key_hex":   fmt.Sprintf("%x", key),
		"length":    keyLength,
		"algorithm": "HMAC-SHA256",
	}, nil
}

func (s *secretGenerationService) generateDatabaseCredentials(config *GenerationConfig) (map[string]interface{}, error) {
	// Generate username and password
	usernameLength := 12
	if config.Length > 0 && config.Length < 20 {
		usernameLength = config.Length
	}

	username, err := s.generateRandomString(usernameLength, "abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return nil, err
	}

	passwordConfig := &GenerationConfig{
		Length:         16,
		IncludeUpper:   true,
		IncludeLower:   true,
		IncludeNumbers: true,
		IncludeSymbols: false, // Avoid symbols that might cause issues in connection strings
	}

	passwordResult, err := s.generatePassword(passwordConfig)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"username": config.Prefix + username,
		"password": passwordResult["password"],
		"type":     "database_credentials",
	}, nil
}

func (s *secretGenerationService) generateSSHKeyPair(config *GenerationConfig) (map[string]interface{}, error) {
	keySize := config.KeySize
	if keySize < 2048 {
		keySize = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	// Generate SSH private key in OpenSSH format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// Generate SSH public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH public key: %w", err)
	}

	publicKeyStr := string(ssh.MarshalAuthorizedKey(publicKey))

	return map[string]interface{}{
		"private_key": privateKeyStr,
		"public_key":  strings.TrimSpace(publicKeyStr),
		"key_size":    keySize,
		"type":        "ssh-rsa",
	}, nil
}

func (s *secretGenerationService) generateOAuthCredentials(config *GenerationConfig) (map[string]interface{}, error) {
	clientID, err := s.generateRandomString(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil {
		return nil, err
	}

	clientSecret, err := s.generateRandomString(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"client_id":     config.Prefix + clientID,
		"client_secret": clientSecret,
		"type":          "oauth2_credentials",
	}, nil
}

func (s *secretGenerationService) generateGenericSecret(config *GenerationConfig) (map[string]interface{}, error) {
	length := config.Length
	if length == 0 {
		length = 32
	}

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	value, err := s.generateRandomString(length, charset)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"value":  config.Prefix + value + config.Suffix,
		"length": len(value),
		"type":   "generic",
	}, nil
}

// Helper method to generate random strings
func (s *secretGenerationService) generateRandomString(length int, charset string) (string, error) {
	result := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}
