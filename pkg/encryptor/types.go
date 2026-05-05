// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"encoding/hex"
	"time"
)

// EncryptionConfig holds the encryption configuration.
type EncryptionConfig struct {
	// KeyringFile is the path to a YAML file containing the keyring.
	// The YAML file contains a list of keys with id, timestamp, and key fields.
	// Encryption always uses the latest key (by timestamp).
	// Decryption uses the key ID embedded in the encrypted data.
	KeyringFile string `json:"keyringFile,omitempty"`

	// keyring holds the loaded keys (populated by LoadKeyring)
	keyring *Keyring
}

// KeyEntry represents a single key entry in the keyring YAML file.
type KeyEntry struct {
	// ID is the unique identifier for this key
	ID string `yaml:"id" json:"id"`
	// Timestamp indicates when this key was created/added
	Timestamp time.Time `yaml:"timestamp" json:"timestamp"`
	// Key is the hex-encoded 32-byte encryption key
	Key string `yaml:"key" json:"key"`
}

// Keyring holds multiple encryption keys indexed by their IDs.
// This enables key rotation while still being able to decrypt older backups.
type Keyring struct {
	// keys maps key IDs to their 32-byte encryption keys
	keys map[string][32]byte
	// latestKeyID is the ID of the key with the most recent timestamp (used for encryption)
	latestKeyID string
	// latestTimestamp is the timestamp of the latest key
	latestTimestamp time.Time
}

// NewKeyring creates a new empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		keys: make(map[string][32]byte),
	}
}

// AddKey adds a key to the keyring with the given ID and timestamp.
// If this key has the latest timestamp, it becomes the primary key for encryption.
func (k *Keyring) AddKey(id string, key [32]byte, timestamp time.Time) {
	k.keys[id] = key
	// Update latest key if this is the most recent
	if k.latestKeyID == "" || timestamp.After(k.latestTimestamp) {
		k.latestKeyID = id
		k.latestTimestamp = timestamp
	}
}

// GetKey retrieves a key by its ID. Returns the key and true if found, zero key and false otherwise.
func (k *Keyring) GetKey(id string) ([32]byte, bool) {
	key, ok := k.keys[id]
	return key, ok
}

// GetLatestKey returns the latest key (by timestamp) used for encryption.
func (k *Keyring) GetLatestKey() ([32]byte, error) {
	if k.latestKeyID == "" {
		return [32]byte{}, ErrNoKeysInKeyring
	}
	key, ok := k.keys[k.latestKeyID]
	if !ok {
		return [32]byte{}, ErrLatestKeyNotFound
	}
	return key, nil
}

// GetLatestKeyID returns the ID of the latest key (by timestamp).
func (k *Keyring) GetLatestKeyID() string {
	return k.latestKeyID
}

// ListKeyIDs returns all key IDs in the keyring.
func (k *Keyring) ListKeyIDs() []string {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	return ids
}

// Size returns the number of keys in the keyring.
func (k *Keyring) Size() int {
	return len(k.keys)
}

// Enabled returns true if encryption is configured.
func (c *EncryptionConfig) Enabled() bool {
	return c != nil && c.KeyringFile != ""
}

// GetKeyring returns the loaded keyring. Loads lazily on first access.
// Returns nil if encryption is not enabled.
func (c *EncryptionConfig) GetKeyring() *Keyring {
	if !c.Enabled() {
		return nil
	}
	if c.keyring == nil {
		_ = c.LoadKeyring() // lazy loading
	}
	return c.keyring
}

// SetKeyring sets the keyring (used for testing or manual configuration).
func (c *EncryptionConfig) SetKeyring(kr *Keyring) {
	c.keyring = kr
}

// ParseHexKey parses a hex-encoded key string into a 32-byte key.
func ParseHexKey(hexKey string) ([32]byte, error) {
	var key [32]byte
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, err
	}
	if len(decoded) != 32 {
		return key, ErrInvalidKeyLength
	}
	copy(key[:], decoded)
	return key, nil
}
