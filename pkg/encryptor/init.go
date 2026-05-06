// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	druidconfigv1alpha1 "github.com/gardener/etcd-druid/api/config/v1alpha1"
)

// LoadEncryptionConfigFromFile loads an EncryptionConfiguration from a JSON file.
func LoadEncryptionConfigFromFile(configFile string) (*druidconfigv1alpha1.EncryptionConfiguration, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption config file %s: %w", configFile, err)
	}

	config := &druidconfigv1alpha1.EncryptionConfiguration{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse encryption config file %s: %w", configFile, err)
	}

	return config, nil
}

// Validate validates the encryption config.
func Validate(c *druidconfigv1alpha1.EncryptionConfiguration) error {
	if !Enabled(c) {
		return nil
	}

	// Validate that keys are present and valid
	if c.AesGcmProvider != nil {
		for _, entry := range c.AesGcmProvider.Keys {
			if entry.Name == "" {
				return fmt.Errorf("keyring entry missing required 'name' field")
			}
			if entry.Secret == "" {
				return fmt.Errorf("keyring entry '%s' missing required 'secret' field", entry.Name)
			}
			if _, err := ParseHexKey(entry.Secret); err != nil {
				return fmt.Errorf("invalid key for entry '%s': %w", entry.Name, err)
			}
		}
	}

	// AesCbc is not supported
	if c.AesCbcProvider != nil && len(c.AesCbcProvider.Keys) > 0 {
		return fmt.Errorf("AES-CBC provider is not supported, use AES-GCM instead")
	}

	return nil
}

// BuildKeyring builds a Keyring from the EncryptionConfiguration.
// The first key in the list is considered the latest (primary) key for encryption.
func BuildKeyring(c *druidconfigv1alpha1.EncryptionConfiguration) (*Keyring, error) {
	keyring := NewKeyring()
	if Enabled(c) {
		for i := len(c.AesGcmProvider.Keys) - 1; i >= 0; i-- {
			entry := c.AesGcmProvider.Keys[i]
			if entry.Name == "" {
				return nil, fmt.Errorf("keyring entry missing required 'name' field")
			}
			if entry.Secret == "" {
				return nil, fmt.Errorf("keyring entry '%s' missing required 'secret' field", entry.Name)
			}
			keyring.Keys[entry.Name] = KeyEntry{
				ID:        entry.Name,
				Timestamp: time.Now(),
				Key:       entry.Secret,
			}
		}
	}
	// Set the first key in the list as the latest (primary) key
	if len(c.AesGcmProvider.Keys) > 0 {
		keyring.PrimaryKeyID = c.AesGcmProvider.Keys[0].Name
	}

	keyring = SyncKeyWithBackup(keyring, objectStore)
	if !Enabled(c) {
		keyring.PrimaryKeyID = ""
	} else {
		for _, entry := range keyring.Keys {
			if entry.Timestamp.After(keyring.Keys[keyring.PrimaryKeyID].Timestamp) {
				return nil, fmt.Errorf("key ID '%s' has a timestamp after the primary key '%s'", entry.ID, keyring.PrimaryKeyID)
			}
		}
	}

	return keyring, nil
}
