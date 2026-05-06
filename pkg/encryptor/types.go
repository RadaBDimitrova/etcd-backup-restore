// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"encoding/hex"
	"time"

	druidconfigv1alpha1 "github.com/gardener/etcd-druid/api/config/v1alpha1"
)

// // EncryptionConfig holds the encryption configuration.
// type EncryptionConfig struct {
// 	// KeyringFile is the path to a YAML file containing the keyring.
// 	// The YAML file contains a list of keys with id, timestamp, and key fields.
// 	// Encryption always uses the latest key (by timestamp).
// 	// Decryption uses the key ID embedded in the encrypted data.
// 	KeyringFile string `json:"keyringFile,omitempty"`

// 	// keyring holds the loaded keys (populated by LoadKeyring)
// 	keyring *Keyring
// }

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
	// Keys maps key IDs to their 32-byte encryption keys
	Keys map[string]KeyEntry
	// PrimaryKeyID is the ID of the key with the most recent timestamp (used for encryption)
	PrimaryKeyID string
}

// NewKeyring creates a new empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		Keys: make(map[string]KeyEntry),
	}
}

func (kr *Keyring) Enabled() bool {
	return len(kr.Keys) > 0 && kr.PrimaryKeyID != ""
}

// Enabled returns true if encryption is configured.
func Enabled(c *druidconfigv1alpha1.EncryptionConfiguration) bool {
	return c != nil && ((c.AesGcmProvider != nil && len(c.AesGcmProvider.Keys) > 0) ||
		(c.AesCbcProvider != nil && len(c.AesCbcProvider.Keys) > 0))
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
