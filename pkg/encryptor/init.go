// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// NewEncryptorConfig returns the encryption config with default values.
func NewEncryptorConfig() *EncryptionConfig {
	return &EncryptionConfig{
		KeyringFile: "",
	}
}

// AddFlags adds the flags to flagset.
func (c *EncryptionConfig) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.KeyringFile, "encryption-keyring-file", c.KeyringFile, "path to YAML file containing encryption keys (encryption uses latest key by timestamp, decryption uses key ID from backup)")
}

// Validate validates the encryption config.
func (c *EncryptionConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}

	info, err := os.Stat(c.KeyringFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("encryption keyring file does not exist: %s", c.KeyringFile)
		}
		return fmt.Errorf("failed to access encryption keyring file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("encryption keyring path is a directory, expected a YAML file: %s", c.KeyringFile)
	}

	return nil
}

// LoadKeyring loads the keyring from the specified YAML file.
func (c *EncryptionConfig) LoadKeyring() error {
	if !c.Enabled() {
		return nil
	}

	data, err := os.ReadFile(c.KeyringFile)
	if err != nil {
		return fmt.Errorf("failed to read keyring file: %w", err)
	}

	var entries []KeyEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse keyring YAML: %w", err)
	}

	if len(entries) == 0 {
		return ErrNoKeysInKeyring
	}

	keyring := NewKeyring()

	for _, entry := range entries {
		if entry.ID == "" {
			return fmt.Errorf("keyring entry missing required 'id' field")
		}
		if entry.Key == "" {
			return fmt.Errorf("keyring entry '%s' missing required 'key' field", entry.ID)
		}

		key, err := ParseHexKey(entry.Key)
		if err != nil {
			return fmt.Errorf("failed to parse key for entry '%s': %w", entry.ID, err)
		}

		keyring.AddKey(entry.ID, key, entry.Timestamp)
	}

	if keyring.GetLatestKeyID() == "" {
		return fmt.Errorf("no valid keys found in keyring file")
	}

	c.keyring = keyring
	return nil
}

// GetKey returns the latest encryption key (by timestamp) for encrypting new backups.
// Returns a zero key if encryption is not enabled.
// Loads the keyring lazily on first access.
func (c *EncryptionConfig) GetKey() ([32]byte, error) {
	var key [32]byte

	if !c.Enabled() {
		return key, nil
	}

	if err := c.ensureKeyringLoaded(); err != nil {
		return key, err
	}
	return c.keyring.GetLatestKey()
}

// GetKeyByID retrieves a key by its ID from the keyring.
// This is used during decryption to find the correct key for a snapshot.
// Loads the keyring lazily on first access.
func (c *EncryptionConfig) GetKeyByID(keyID string) ([32]byte, error) {
	var key [32]byte

	if !c.Enabled() {
		return key, fmt.Errorf("encryption not enabled")
	}

	if err := c.ensureKeyringLoaded(); err != nil {
		return key, err
	}

	key, ok := c.keyring.GetKey(keyID)
	if !ok {
		return key, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return key, nil
}

// GetLatestKeyID returns the latest key ID (by timestamp) used for encrypting new backups.
// Returns empty string if encryption is not enabled or keyring not loaded.
func (c *EncryptionConfig) GetLatestKeyID() string {
	if c.Enabled() && c.keyring != nil {
		return c.keyring.GetLatestKeyID()
	}
	return ""
}

// ensureKeyringLoaded loads the keyring if it hasn't been loaded yet.
func (c *EncryptionConfig) ensureKeyringLoaded() error {
	if c.keyring != nil {
		return nil
	}
	return c.LoadKeyring()
}
