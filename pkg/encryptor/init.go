// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
)

// NewEncryptorConfig returns the encryption config with default values.
func NewEncryptorConfig() *EncryptionConfig {
	return &EncryptionConfig{
		KeyFile: "",
	}
}

// AddFlags adds the flags to flagset.
func (c *EncryptionConfig) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.KeyFile, "encryption-key-file", c.KeyFile, "path to the file containing the 32-byte encryption key (enables encryption when set)")
}

// Validate validates the encryption config.
func (c *EncryptionConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}

	// Check if the key file exists and is readable
	info, err := os.Stat(c.KeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("encryption key file does not exist: %s", c.KeyFile)
		}
		return fmt.Errorf("failed to access encryption key file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("encryption key file path is a directory: %s", c.KeyFile)
	}

	return nil
}

// GetKey reads and returns the 32-byte encryption key from the configured key file.
// Returns a zero key if encryption is not enabled.
func (c *EncryptionConfig) GetKey() ([32]byte, error) {
	var key [32]byte

	if !c.Enabled() {
		return key, nil
	}

	keyData, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return key, fmt.Errorf("failed to read encryption key from file %s: %w", c.KeyFile, err)
	}

	if len(keyData) != 32 {
		return key, fmt.Errorf("encryption key must be 32 bytes long, got %d bytes", len(keyData))
	}

	copy(key[:], keyData)
	return key, nil
}
