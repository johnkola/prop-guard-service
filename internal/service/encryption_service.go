package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	gcmIVLength  = 12
	gcmTagLength = 16
)

type EncryptionService interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encryptedData string) (string, error)
	GenerateHash(data string) string
	GenerateDataKey() ([]byte, error)
}

type encryptionService struct {
	masterKey []byte
}

func NewEncryptionService(masterKeyString string) EncryptionService {
	hash := sha256.Sum256([]byte(masterKeyString))
	return &encryptionService{
		masterKey: hash[:],
	}
}

func (s *encryptionService) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcmIVLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine nonce and ciphertext
	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)

	return base64.StdEncoding.EncodeToString(combined), nil
}

func (s *encryptionService) Decrypt(encryptedData string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(decodedData) < gcmIVLength {
		return "", fmt.Errorf("invalid encrypted data")
	}

	nonce := decodedData[:gcmIVLength]
	ciphertext := decodedData[gcmIVLength:]

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

func (s *encryptionService) GenerateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (s *encryptionService) GenerateDataKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	return key, nil
}
