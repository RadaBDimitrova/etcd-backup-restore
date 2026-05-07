// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"sigs.k8s.io/yaml"

	druidconfigv1alpha1 "github.com/gardener/etcd-druid/api/config/v1alpha1"
	druidconfigv1alpha1validation "github.com/gardener/etcd-druid/api/config/v1alpha1/validation"
)

// FetchKeyringFunc fetches the encrypted keyring data from the store.
// Returns nil, nil if no keyring exists. This allows the caller to provide
// any implementation (e.g., using SnapStore.Fetch with a keyring snapshot).
type FetchKeyringFunc func() ([]byte, error)

// SaveKeyringFunc saves the encrypted keyring data to the store.
type SaveKeyringFunc func(data []byte) error

// LoadEncryptionConfigFromFile loads an EncryptionConfiguration from a JSON file.
func LoadEncryptionConfigFromFile(configFile string) (*druidconfigv1alpha1.EncryptionConfiguration, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption config file %s: %w", configFile, err)
	}

	config := &druidconfigv1alpha1.EncryptionConfiguration{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse encryption config file %s: %w", configFile, err)
	}

	return config, nil
}

// Validate validates the encryption config.
func Validate(c *druidconfigv1alpha1.EncryptionConfiguration) error {
	if !Enabled(c) {
		return nil
	}

	if errList := druidconfigv1alpha1validation.ValidateEncryptionConfiguration(c); len(errList) > 0 {
		return fmt.Errorf("provided encryption configuration is not valid: %w", errList.ToAggregate())
	}

	for i, provider := range c.Providers {
		if provider.AesGcmProvider != nil {
			continue
		}

		if provider.AesCbcProvider != nil {
			return fmt.Errorf("provider not yet supported: aescbc")
		}

		return fmt.Errorf("unknown provider at index %d", i)
	}

	return nil
}

// BuildKeyring builds a Keyring from the EncryptionConfiguration.
// The first key in the list is considered the latest (primary) key for encryption.
func BuildKeyring(c *druidconfigv1alpha1.EncryptionConfiguration) (*Keyring, error) {
	var (
		keyring = NewKeyring()
		first   string
	)

	if !Enabled(c) {
		return keyring, nil
	}

	for _, provider := range c.Providers {
		if provider.AesGcmProvider == nil {
			continue
		}

		for _, key := range provider.AesGcmProvider.Keys {
			// Validate that the secret is valid base64, but store it encoded
			// (decoding happens at usage time)
			if _, err := base64.RawStdEncoding.DecodeString(string(key.Secret)); err != nil {
				return nil, fmt.Errorf("error decoding secret key: %w", err)
			}

			if first == "" {
				first = key.Name
			}

			keyring.Keys[key.Name] = KeyEntry{
				ID:        key.Name,
				Timestamp: time.Now(),
				Key:       string(key.Secret), // Store base64-encoded
			}
		}
	}

	// Set the first key in the list as the latest (primary) key
	keyring.PrimaryKeyID = first

	return keyring, nil
}

// SyncKeyringWithBackup synchronizes the keyring with the backup store.
// It fetches any keys from the store that aren't in the local keyring,
// and saves the local keyring to the store if it has new keys.
// Pass nil for fetchFn/saveFn if no store sync is needed.
func SyncKeyringWithBackup(keyring *Keyring, fetchFn FetchKeyringFunc, saveFn SaveKeyringFunc) *Keyring {
	if fetchFn == nil || saveFn == nil {
		return keyring
	}

	// Fetch encrypted keyring from store
	backupKeyring, err := fetchKeyringFromStore(fetchFn, keyring)
	if err != nil {
		// Log error but continue - store might not have a keyring yet
		return keyring
	}

	if backupKeyring == nil {
		// No keyring in store - save our keyring if we have keys
		if len(keyring.Keys) > 0 {
			_ = saveKeyringToStore(saveFn, keyring)
		}
		return keyring
	}

	// Merge keys: add any keys from backup that aren't in local keyring
	keysAdded := false
	for id, entry := range backupKeyring.Keys {
		if _, exists := keyring.Keys[id]; !exists {
			keyring.Keys[id] = entry
			keysAdded = true
		}
	}

	// Check if local has keys not in backup
	localHasMoreKeys := false
	for id := range keyring.Keys {
		if _, exists := backupKeyring.Keys[id]; !exists {
			localHasMoreKeys = true
			break
		}
	}

	// If we have keys not in backup, or we added keys, update the store
	if localHasMoreKeys || keysAdded {
		_ = saveKeyringToStore(saveFn, keyring)
	}

	return keyring
}

// fetchKeyringFromStore decrypts and returns the keyring stored in the snapstore.
// Returns nil, nil if no keyring exists in the store.
func fetchKeyringFromStore(fetchFn FetchKeyringFunc, decryptionKeyring *Keyring) (*Keyring, error) {
	data, err := fetchFn()
	if err != nil {
		return nil, fmt.Errorf("failed to get keyring data: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	// Parse header: 1 byte key ID length + key ID + 12 bytes nonce + encrypted data
	if len(data) < 2 {
		return nil, fmt.Errorf("keyring data too short")
	}

	keyIDLen := int(data[0])
	if len(data) < 1+keyIDLen+12+1 {
		return nil, fmt.Errorf("keyring data too short for header")
	}

	keyID := string(data[1 : 1+keyIDLen])
	nonce := data[1+keyIDLen : 1+keyIDLen+12]
	ciphertext := data[1+keyIDLen+12:]

	// Find the key to decrypt with
	keyEntry, exists := decryptionKeyring.Keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key ID '%s' not found in keyring", keyID)
	}

	// Parse the hex key
	keyBytes, err := base64.RawStdEncoding.DecodeString(keyEntry.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Decrypt
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keyring: %w", err)
	}

	// Unmarshal keyring
	var storedKeyring Keyring
	if err := json.Unmarshal(plaintext, &storedKeyring); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keyring: %w", err)
	}

	return &storedKeyring, nil
}

// saveKeyringToStore encrypts and saves the keyring to the snapstore.
func saveKeyringToStore(saveFn SaveKeyringFunc, keyring *Keyring) error {
	if keyring.PrimaryKeyID == "" {
		return fmt.Errorf("no primary key ID set")
	}

	keyEntry, exists := keyring.Keys[keyring.PrimaryKeyID]
	if !exists {
		return fmt.Errorf("primary key ID '%s' not found in keyring", keyring.PrimaryKeyID)
	}

	// Parse the hex key
	keyBytes, err := base64.RawStdEncoding.DecodeString(keyEntry.Key)
	if err != nil {
		return fmt.Errorf("failed to parse key: %w", err)
	}

	// Marshal keyring to JSON
	plaintext, err := json.Marshal(keyring)
	if err != nil {
		return fmt.Errorf("failed to marshal keyring: %w", err)
	}

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Build output: key ID length + key ID + nonce + ciphertext
	keyIDBytes := []byte(keyring.PrimaryKeyID)
	if len(keyIDBytes) > 255 {
		return fmt.Errorf("key ID too long")
	}

	var buf bytes.Buffer
	buf.WriteByte(byte(len(keyIDBytes)))
	buf.Write(keyIDBytes)
	buf.Write(nonce)
	buf.Write(ciphertext)

	return saveFn(buf.Bytes())
}
