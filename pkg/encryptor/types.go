// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package encryptor

// EncryptionConfig holds the encryption configuration.
type EncryptionConfig struct {
	// KeyFile is the path to the file containing the 32-byte encryption key.
	// If set, encryption is enabled; if empty, encryption is disabled.
	KeyFile string `json:"keyFile,omitempty"`
}

// Enabled returns true if encryption is configured (i.e., a key file is specified).
func (c *EncryptionConfig) Enabled() bool {
	return c != nil && c.KeyFile != ""
}
