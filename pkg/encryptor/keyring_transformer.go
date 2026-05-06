// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	if len(keyring.Keys) == 0 {
		return nil, ErrNoKeysInKeyring
	}
	return &KeyringTransformer{keyring: keyring}, nil
}

// TransformToStorage returns a reader that encrypts data using the latest key (by timestamp),
// embedding the key ID in the output stream.
func (kt *KeyringTransformer) TransformToStorage(r io.ReadCloser) (io.ReadCloser, error) {
	if !kt.keyring.Enabled() {
		return r, nil
	}
	keyID := kt.keyring.PrimaryKeyID
	latestKey := kt.keyring.Keys[keyID].Key

	if len(keyID) > MaxKeyIDLength {
		return nil, fmt.Errorf("key ID length %d exceeds maximum %d", len(keyID), MaxKeyIDLength)
	}

	keyBytes, err := base64.RawStdEncoding.DecodeString(latestKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest key: %w", err)
	}

	block, err := aes.NewCipher(keyBytes[:])
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
	key, ok := kt.keyring.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}

	keyBytes, err := base64.RawStdEncoding.DecodeString(key.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Create the cipher for this key
	block, err := aes.NewCipher(keyBytes[:])
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

// DecryptSnapshot decrypts a snapshot using the provided EncryptionConfiguration.
// Reads the key ID from the encrypted data header and uses the corresponding key.
// Syncs the keyring with the backup store on first call.
func DecryptSnapshot(r io.ReadCloser, keyring *Keyring) (io.ReadCloser, error) {
	keyring.SyncOnce()
	kt, err := NewKeyringTransformer(keyring)
	if err != nil {
		return nil, err
	}
	return kt.TransformFromStorage(r)
}

// EncryptSnapshot encrypts a snapshot using the provided EncryptionConfiguration.
// Uses the latest key (by timestamp) and embeds the key ID in the output.
// Syncs the keyring with the backup store on first call.
func EncryptSnapshot(r io.ReadCloser, keyring *Keyring) (io.ReadCloser, error) {
	if keyring == nil {
		return r, fmt.Errorf("empty keyring")
	}
	keyring.SyncOnce()

	kt, err := NewKeyringTransformer(keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to build keyring: %w", err)
	}
	return kt.TransformToStorage(r)
}
