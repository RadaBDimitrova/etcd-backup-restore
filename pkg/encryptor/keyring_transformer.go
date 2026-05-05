// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// KeyringFormatVersion is the version byte for the keyring encryption format.
	KeyringFormatVersion = 0x01
	// MaxKeyIDLength is the maximum allowed length for a key ID.
	MaxKeyIDLength = 255
)

// KeyringTransformer provides streaming encryption and decryption with key ID support.
// It embeds the key ID in the encrypted stream to enable key rotation.
//
// Encrypted format: [version=0x01][keyID length (1 byte)][keyID bytes][12-byte nonce][chunks...]
type KeyringTransformer struct {
	keyring *Keyring
}

// NewKeyringTransformer creates a new KeyringTransformer with the given keyring.
func NewKeyringTransformer(keyring *Keyring) (*KeyringTransformer, error) {
	if keyring == nil {
		return nil, fmt.Errorf("keyring cannot be nil")
	}
	if keyring.Size() == 0 {
		return nil, ErrNoKeysInKeyring
	}
	return &KeyringTransformer{keyring: keyring}, nil
}

// TransformToStorage returns a reader that encrypts data using the latest key (by timestamp),
// embedding the key ID in the output stream.
func (kt *KeyringTransformer) TransformToStorage(r io.ReadCloser) (io.ReadCloser, error) {
	latestKey, err := kt.keyring.GetLatestKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest key: %w", err)
	}

	keyID := kt.keyring.GetLatestKeyID()
	if len(keyID) == 0 {
		return nil, fmt.Errorf("latest key ID cannot be empty")
	}
	if len(keyID) > MaxKeyIDLength {
		return nil, fmt.Errorf("key ID length %d exceeds maximum %d", len(keyID), MaxKeyIDLength)
	}

	block, err := aes.NewCipher(latestKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	baseNonce := make([]byte, NonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build the header: version + keyID length + keyID + nonce
	header := make([]byte, 0, 1+1+len(keyID)+NonceSize)
	header = append(header, KeyringFormatVersion)
	header = append(header, byte(len(keyID)))
	header = append(header, []byte(keyID)...)
	header = append(header, baseNonce...)

	return &encryptingReader{
		src:       r,
		aead:      aead,
		baseNonce: baseNonce,
		chunkNum:  0,
		buf:       make([]byte, ChunkSize),
		pending:   header, // Start by emitting the header
	}, nil
}

// TransformFromStorage returns a reader that decrypts data, reading the key ID
// from the stream and looking up the corresponding key in the keyring.
func (kt *KeyringTransformer) TransformFromStorage(r io.ReadCloser) (io.ReadCloser, error) {
	// Read the version byte
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, versionBuf); err != nil {
		return nil, fmt.Errorf("failed to read version byte: %w", err)
	}

	version := versionBuf[0]
	if version != KeyringFormatVersion {
		return nil, fmt.Errorf("unsupported encryption format version: %d", version)
	}

	// Read the key ID length
	keyIDLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, keyIDLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read key ID length: %w", err)
	}
	keyIDLen := int(keyIDLenBuf[0])
	if keyIDLen == 0 {
		return nil, fmt.Errorf("key ID length cannot be zero")
	}

	// Read the key ID
	keyIDBuf := make([]byte, keyIDLen)
	if _, err := io.ReadFull(r, keyIDBuf); err != nil {
		return nil, fmt.Errorf("failed to read key ID: %w", err)
	}
	keyID := string(keyIDBuf)

	// Look up the key in the keyring
	key, ok := kt.keyring.GetKey(keyID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}

	// Create the cipher for this key
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read the base nonce
	baseNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	return &decryptingReader{
		src:       r,
		aead:      aead,
		baseNonce: baseNonce,
		chunkNum:  0,
	}, nil
}

// DecryptWithKeyring decrypts data encrypted with the keyring format.
// Reads the key ID from the header and looks up the corresponding key.
func DecryptWithKeyring(r io.ReadCloser, keyring *Keyring) (io.ReadCloser, error) {
	kt, err := NewKeyringTransformer(keyring)
	if err != nil {
		return nil, err
	}
	return kt.TransformFromStorage(r)
}

// DecryptSnapshot decrypts a snapshot using the provided EncryptionConfig.
// Reads the key ID from the encrypted data header and uses the corresponding key.
func DecryptSnapshot(r io.ReadCloser, config *EncryptionConfig) (io.ReadCloser, error) {
	if config == nil || !config.Enabled() {
		return r, nil
	}

	keyring := config.GetKeyring()
	if keyring == nil {
		return nil, fmt.Errorf("keyring not loaded; call LoadKeyring() first")
	}
	return DecryptWithKeyring(r, keyring)
}

// EncryptSnapshot encrypts a snapshot using the provided EncryptionConfig.
// Uses the latest key (by timestamp) and embeds the key ID in the output.
func EncryptSnapshot(r io.ReadCloser, config *EncryptionConfig) (io.ReadCloser, error) {
	if config == nil || !config.Enabled() {
		return r, nil
	}

	keyring := config.GetKeyring()
	if keyring == nil {
		return nil, fmt.Errorf("keyring not loaded; call LoadKeyring() first")
	}
	kt, err := NewKeyringTransformer(keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring transformer: %w", err)
	}
	return kt.TransformToStorage(r)
}
