// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

const (
	nonceSize        = 12
	chunkSize        = 1 << 20
	lengthPrefixSize = 4
	gcmOverhead      = 16
	maxChunkLen      = chunkSize + gcmOverhead
)

type encryptionConfiguration struct {
	APIVersion string                `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                `yaml:"kind"       json:"kind"`
	Providers  []encryptionProvider  `yaml:"providers"  json:"providers"`
}

type encryptionProvider struct {
	AesGcm *aesGcmProvider `yaml:"aesgcm" json:"aesgcm"`
}

type aesGcmProvider struct {
	Keys []encryptionKey `yaml:"keys" json:"keys"`
}

type encryptionKey struct {
	Name   string `yaml:"name"   json:"name"`
	Secret string `yaml:"secret" json:"secret"`
}

func main() {
	configPath := flag.String("config", "", "path to etcd-druid EncryptionConfiguration YAML file")
	flag.Parse()

	if *configPath == "" {
		fatal("flag -config is required")
	}

	keyLookup := buildKeyLookup(*configPath)
	args := flag.Args()

	if len(args) >= 2 && args[0] == "keyring" {
		runKeyring(keyLookup, args[1])
	} else {
		runSnapshot(keyLookup, args)
	}
}

func runSnapshot(keyLookup map[string][]byte, args []string) {
	input := openInput(args)
	defer input.Close()

	aead, baseNonce := readSnapshotHeader(input, keyLookup)

	out := os.Stdout
	chunkNum := uint64(0)
	for {
		lenBuf := make([]byte, lengthPrefixSize)
		_, err := io.ReadFull(input, lenBuf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fatal("failed to read chunk length: %v", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen > maxChunkLen {
			fatal("chunk size %d exceeds maximum %d", chunkLen, maxChunkLen)
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			fatal("failed to read ciphertext: %v", err)
		}

		nonce := slices.Clone(baseNonce)
		binary.BigEndian.PutUint64(nonce[nonceSize-8:], binary.BigEndian.Uint64(nonce[nonceSize-8:])^chunkNum)
		chunkNum++

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fatal("failed to decrypt chunk %d: %v", chunkNum-1, err)
		}

		if _, err := out.Write(plaintext); err != nil {
			fatal("failed to write output: %v", err)
		}
	}
}

func runKeyring(keyLookup map[string][]byte, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("failed to read keyring: %v", err)
	}
	if len(data) < 2 {
		fatal("keyring data too short")
	}

	keyIDLen := int(data[0])
	if len(data) < 1+keyIDLen+12+1 {
		fatal("keyring data too short for header")
	}

	keyID := string(data[1 : 1+keyIDLen])
	nonce := data[1+keyIDLen : 1+keyIDLen+12]
	ciphertext := data[1+keyIDLen+12:]

	key, ok := keyLookup[keyID]
	if !ok {
		fatal("key ID %q not found in config", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fatal("failed to create AES cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fatal("failed to create GCM: %v", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fatal("failed to decrypt keyring: %v", err)
	}

	var kr map[string]any
	if err := json.Unmarshal(plaintext, &kr); err != nil {
		fatal("failed to parse keyring JSON: %v", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(kr); err != nil {
		fatal("failed to write output: %v", err)
	}
}

func buildKeyLookup(path string) map[string][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("failed to read config: %v", err)
	}
	var cfg encryptionConfiguration
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fatal("failed to parse config: %v", err)
	}

	m := make(map[string][]byte)
	for _, p := range cfg.Providers {
		if p.AesGcm == nil {
			continue
		}
		for _, key := range p.AesGcm.Keys {
			inner, err := base64.StdEncoding.DecodeString(key.Secret)
			if err != nil {
				fatal("failed to decode outer base64 for key %q: %v", key.Name, err)
			}
			raw, err := base64.RawStdEncoding.DecodeString(string(inner))
			if err != nil {
				fatal("failed to decode inner base64 for key %q: %v", key.Name, err)
			}
			if len(raw) != 32 {
				fatal("key %q must be 32 bytes, got %d", key.Name, len(raw))
			}
			m[key.Name] = raw
		}
	}
	if len(m) == 0 {
		fatal("no AES-GCM keys found in config")
	}
	return m
}

func openInput(args []string) io.ReadCloser {
	if len(args) == 0 || args[0] == "-" {
		return os.Stdin
	}
	f, err := os.Open(args[0])
	if err != nil {
		fatal("failed to open input: %v", err)
	}
	return f
}

func readSnapshotHeader(input io.Reader, keyLookup map[string][]byte) (cipher.AEAD, []byte) {
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(input, versionBuf); err != nil {
		fatal("failed to read version: %v", err)
	}
	if versionBuf[0] != 0x01 {
		fatal("unsupported format version: 0x%02x", versionBuf[0])
	}

	keyIDLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(input, keyIDLenBuf); err != nil {
		fatal("failed to read key ID length: %v", err)
	}
	keyIDLen := int(keyIDLenBuf[0])
	if keyIDLen == 0 {
		fatal("key ID length cannot be zero")
	}

	keyIDBuf := make([]byte, keyIDLen)
	if _, err := io.ReadFull(input, keyIDBuf); err != nil {
		fatal("failed to read key ID: %v", err)
	}
	keyID := string(keyIDBuf)

	key, ok := keyLookup[keyID]
	if !ok {
		fatal("key ID %q not found in config", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fatal("failed to create AES cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fatal("failed to create GCM: %v", err)
	}

	baseNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(input, baseNonce); err != nil {
		fatal("failed to read base nonce: %v", err)
	}

	return aead, baseNonce
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
