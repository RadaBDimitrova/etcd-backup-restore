// Package encryptor provides streaming encryption/decryption using AES-GCM with chunked processing.
// Each chunk is independently encrypted with a unique nonce derived from a base nonce and chunk counter.
// Format: [12-byte base nonce][chunk1][chunk2]...
// Each chunk: [4-byte length (big-endian)][ciphertext with 16-byte auth tag]
package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// NonceSize is the size of the AES-GCM nonce
	NonceSize = 12
	// ChunkSize is the size of plaintext chunks (1 MB)
	ChunkSize = 1024 * 1024
	// LengthPrefixSize is the size of the chunk length prefix
	LengthPrefixSize = 4
)

// Transformer provides streaming encryption and decryption using AES-GCM.
type Transformer struct {
	aead cipher.AEAD
}

// NewTransformer creates a new Transformer with the given 32-byte key.
func NewTransformer(key [32]byte) (*Transformer, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Transformer{aead: aead}, nil
}

// TransformToStorage returns a reader that encrypts data in chunks as it is read.
func (t *Transformer) TransformToStorage(r io.ReadCloser) (io.ReadCloser, error) {
	baseNonce := make([]byte, NonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &encryptingReader{
		src:       r,
		aead:      t.aead,
		baseNonce: baseNonce,
		chunkNum:  0,
		buf:       make([]byte, ChunkSize),
		pending:   baseNonce, // Start by emitting the base nonce
	}, nil
}

// TransformFromStorage returns a reader that decrypts data in chunks as it is read.
func (t *Transformer) TransformFromStorage(r io.ReadCloser) (io.ReadCloser, error) {
	// Read the base nonce first
	baseNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	return &decryptingReader{
		src:       r,
		aead:      t.aead,
		baseNonce: baseNonce,
		chunkNum:  0,
	}, nil
}

// encryptingReader reads plaintext and outputs encrypted chunks.
type encryptingReader struct {
	src       io.ReadCloser
	aead      cipher.AEAD
	baseNonce []byte
	chunkNum  uint64
	buf       []byte
	pending   []byte // encrypted data waiting to be read
	done      bool
}

func (r *encryptingReader) Read(p []byte) (int, error) {
	// If we have pending data, return it first
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	if r.done {
		return 0, io.EOF
	}

	// Read next chunk of plaintext
	n, err := io.ReadFull(r.src, r.buf)
	if err == io.EOF {
		r.done = true
		return 0, io.EOF
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		return 0, fmt.Errorf("failed to read plaintext: %w", err)
	}

	// If we got less than a full chunk, this is the last one
	if err == io.ErrUnexpectedEOF || n < len(r.buf) {
		r.done = true
	}

	plaintext := r.buf[:n]

	// Generate chunk-specific nonce: baseNonce XOR chunkNum
	nonce := make([]byte, NonceSize)
	copy(nonce, r.baseNonce)
	binary.BigEndian.PutUint64(nonce[NonceSize-8:], binary.BigEndian.Uint64(nonce[NonceSize-8:])^r.chunkNum)
	r.chunkNum++

	// Encrypt the chunk
	ciphertext := r.aead.Seal(nil, nonce, plaintext, nil)

	// Prepend length prefix
	lengthPrefix := make([]byte, LengthPrefixSize)
	binary.BigEndian.PutUint32(lengthPrefix, uint32(len(ciphertext)))

	r.pending = append(lengthPrefix, ciphertext...)

	// Return as much as fits in p
	copied := copy(p, r.pending)
	r.pending = r.pending[copied:]
	return copied, nil
}

func (r *encryptingReader) Close() error {
	return r.src.Close()
}

// decryptingReader reads encrypted chunks and outputs plaintext.
type decryptingReader struct {
	src       io.ReadCloser
	aead      cipher.AEAD
	baseNonce []byte
	chunkNum  uint64
	pending   []byte // decrypted data waiting to be read
	done      bool
}

func (r *decryptingReader) Read(p []byte) (int, error) {
	// If we have pending data, return it first
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	if r.done {
		return 0, io.EOF
	}

	// Read chunk length
	lengthBuf := make([]byte, LengthPrefixSize)
	_, err := io.ReadFull(r.src, lengthBuf)
	if err == io.EOF {
		r.done = true
		return 0, io.EOF
	}
	if err != nil {
		return 0, fmt.Errorf("failed to read chunk length: %w", err)
	}

	chunkLen := binary.BigEndian.Uint32(lengthBuf)
	if chunkLen > ChunkSize+uint32(r.aead.Overhead()) {
		return 0, fmt.Errorf("chunk size %d exceeds maximum allowed", chunkLen)
	}

	// Read the ciphertext chunk
	ciphertext := make([]byte, chunkLen)
	_, err = io.ReadFull(r.src, ciphertext)
	if err != nil {
		return 0, fmt.Errorf("failed to read ciphertext chunk: %w", err)
	}

	// Generate chunk-specific nonce
	nonce := make([]byte, NonceSize)
	copy(nonce, r.baseNonce)
	binary.BigEndian.PutUint64(nonce[NonceSize-8:], binary.BigEndian.Uint64(nonce[NonceSize-8:])^r.chunkNum)
	r.chunkNum++

	// Decrypt the chunk
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt chunk %d: %w", r.chunkNum-1, err)
	}

	r.pending = plaintext

	// Return as much as fits in p
	copied := copy(p, r.pending)
	r.pending = r.pending[copied:]
	return copied, nil
}

func (r *decryptingReader) Close() error {
	return r.src.Close()
}

func isEncrypted(snapList []brtypes.Snapshot) bool {
	for _, snap := range snapList {
		if snap.IsEncrypted {
			return true
		}
	}
	return false
}
