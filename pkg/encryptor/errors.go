// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

import "errors"

var (
	// ErrLatestKeyNotFound is returned when the latest key ID does not exist in the keyring.
	ErrLatestKeyNotFound = errors.New("latest key not found in keyring")

	// ErrKeyNotFound is returned when a key ID does not exist in the keyring.
	ErrKeyNotFound = errors.New("key not found in keyring")

	// ErrNoKeysInKeyring is returned when the keyring file contains no valid keys.
	ErrNoKeysInKeyring = errors.New("no keys found in keyring file")

	// ErrInvalidKeyLength is returned when a key is not exactly 32 bytes.
	ErrInvalidKeyLength = errors.New("encryption key must be exactly 32 bytes")
)
