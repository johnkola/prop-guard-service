package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// Common errors
var (
	ErrNotFound    = errors.New("key not found")
	ErrInvalidData = errors.New("invalid data")
)

// BadgerClient wraps the BadgerDB client
type BadgerClient struct {
	db *badger.DB
}

// BadgerConfig holds configuration for BadgerDB
type BadgerConfig struct {
	Dir                string
	ValueLogFileSize   int64
	MemTableSize       int64
	BlockCacheSize     int64
	IndexCacheSize     int64
	NumVersionsToKeep  int
	NumLevelZeroTables int
	Compression        bool
	EncryptionKey      []byte
	BaseTableSize      int64
	ValueThreshold     int64
}

// DefaultBadgerConfig returns default configuration
func DefaultBadgerConfig(dir string) BadgerConfig {
	return BadgerConfig{
		Dir:                dir,
		ValueLogFileSize:   1 << 28,   // 256MB
		MemTableSize:       64 << 20,  // 64MB
		BlockCacheSize:     256 << 20, // 256MB
		IndexCacheSize:     100 << 20, // 100MB
		NumVersionsToKeep:  1,
		NumLevelZeroTables: 5,
		Compression:        true,
		BaseTableSize:      2 << 20, // 2MB
		ValueThreshold:     1 << 20, // 1MB
	}
}

// NewBadgerClient creates a new BadgerDB client
func NewBadgerClient(config BadgerConfig) (*BadgerClient, error) {
	opts := badger.DefaultOptions(config.Dir)

	// Configure performance options
	opts.ValueLogFileSize = config.ValueLogFileSize
	opts.MemTableSize = config.MemTableSize
	opts.BlockCacheSize = config.BlockCacheSize
	opts.IndexCacheSize = config.IndexCacheSize
	opts.NumVersionsToKeep = config.NumVersionsToKeep
	opts.NumLevelZeroTables = config.NumLevelZeroTables

	// Configure value threshold and base table size to prevent errors
	if config.BaseTableSize > 0 {
		opts.BaseTableSize = config.BaseTableSize
	}
	if config.ValueThreshold > 0 {
		opts.ValueThreshold = config.ValueThreshold
	}

	// Disable compression for now
	// opts.Compression can be set later if needed

	// Configure encryption if key provided
	if len(config.EncryptionKey) > 0 {
		opts.EncryptionKey = config.EncryptionKey
		opts.EncryptionKeyRotationDuration = 10 * 24 * time.Hour // Rotate every 10 days
	}

	// Open the database
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	// Start garbage collection goroutine
	go runGC(db)

	return &BadgerClient{db: db}, nil
}

// runGC runs garbage collection periodically
func runGC(db *badger.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
	again:
		err := db.RunValueLogGC(0.5)
		if err == nil {
			goto again
		}
	}
}

// Close closes the database connection
func (c *BadgerClient) Close() error {
	return c.db.Close()
}

// Get retrieves a value by key
func (c *BadgerClient) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte

	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		value, err = item.ValueCopy(nil)
		return err
	})

	if err == badger.ErrKeyNotFound {
		return nil, ErrNotFound
	}

	return value, err
}

// Set stores a key-value pair
func (c *BadgerClient) Set(ctx context.Context, key string, value []byte) error {
	return c.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), value)
	})
}

// SetWithTTL stores a key-value pair with expiration
func (c *BadgerClient) SetWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), value).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

// Delete removes a key
func (c *BadgerClient) Delete(ctx context.Context, key string) error {
	return c.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// Exists checks if a key exists
func (c *BadgerClient) Exists(ctx context.Context, key string) (bool, error) {
	err := c.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		return err
	})

	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetAll retrieves all keys with a prefix
func (c *BadgerClient) GetAll(ctx context.Context, prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	err := c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefix)

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())

			value, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			result[key] = value
		}
		return nil
	})

	return result, err
}

// Transaction executes multiple operations atomically
func (c *BadgerClient) Transaction(ctx context.Context, fn func(txn *Transaction) error) error {
	return c.db.Update(func(btxn *badger.Txn) error {
		txn := &Transaction{txn: btxn}
		return fn(txn)
	})
}

// Transaction wraps BadgerDB transaction
type Transaction struct {
	txn *badger.Txn
}

// Get retrieves a value in transaction
func (t *Transaction) Get(key string) ([]byte, error) {
	item, err := t.txn.Get([]byte(key))
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return item.ValueCopy(nil)
}

// Set stores a value in transaction
func (t *Transaction) Set(key string, value []byte) error {
	return t.txn.Set([]byte(key), value)
}

// Delete removes a key in transaction
func (t *Transaction) Delete(key string) error {
	return t.txn.Delete([]byte(key))
}

// SetJSON stores a JSON object
func (c *BadgerClient) SetJSON(ctx context.Context, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return c.Set(ctx, key, data)
}

// GetJSON retrieves and unmarshals a JSON object
func (c *BadgerClient) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := c.Get(ctx, key)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// Backup creates a backup of the database
func (c *BadgerClient) Backup(ctx context.Context, w io.Writer) error {
	_, err := c.db.Backup(w, 0)
	return err
}

// Restore restores the database from a backup
func (c *BadgerClient) Restore(ctx context.Context, r io.Reader) error {
	return c.db.Load(r, 256)
}

// GetStats returns database statistics
func (c *BadgerClient) GetStats() map[string]interface{} {
	lsm, vlog := c.db.Size()

	return map[string]interface{}{
		"lsm_size":   lsm,
		"vlog_size":  vlog,
		"num_keys":   c.getKeyCount(),
		"num_tables": c.db.Tables(),
	}
}

// getKeyCount returns approximate number of keys
func (c *BadgerClient) getKeyCount() int64 {
	var count int64

	c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	return count
}

// Ping checks if the database is responsive
func (c *BadgerClient) Ping() error {
	return c.db.View(func(txn *badger.Txn) error {
		return nil
	})
}

// Disconnect is an alias for Close (compatibility)
func (c *BadgerClient) Disconnect(ctx context.Context) error {
	return c.Close()
}
