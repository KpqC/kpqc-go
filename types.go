// Package kpqc is deprecated; use kpqc.dev instead.
//
// Deprecated: use kpqc.dev instead.
package kpqc

import (
	"errors"
	"fmt"
)

// ErrInvalidSize indicates that a key, signature, or ciphertext has the wrong
// number of bytes.
var ErrInvalidSize = errors.New("kpqc: invalid input size")

// ErrContextTooLong indicates that a signature context exceeds 255 bytes.
var ErrContextTooLong = errors.New("kpqc: context cannot exceed 255 bytes")

// NativeError reports a failure returned by an algorithm implementation.
type NativeError struct {
	Operation string
	Status    int
}

func (e *NativeError) Error() string {
	return fmt.Sprintf("kpqc: %s failed with status %d", e.Operation, e.Status)
}

// KeyPair contains a public key and its corresponding secret key.
type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// EncapsulatedSecret contains a ciphertext and the shared secret established
// for its recipient.
type EncapsulatedSecret struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// SignatureSizes describes the fixed-size values used by a signature scheme.
type SignatureSizes struct {
	PublicKey int
	SecretKey int
	Signature int
}

// KEMSizes describes the fixed-size values used by a key-encapsulation
// mechanism.
type KEMSizes struct {
	PublicKey    int
	SecretKey    int
	Ciphertext   int
	SharedSecret int
}

// SignatureAlgorithm is a detached-signature scheme. Sign and Verify use an
// empty context; their WithContext variants bind the signature to a context of
// at most 255 bytes.
type SignatureAlgorithm interface {
	ID() string
	Sizes() SignatureSizes
	GenerateKeyPair() (KeyPair, error)
	Sign(message, secretKey []byte) ([]byte, error)
	SignWithContext(message, secretKey, context []byte) ([]byte, error)
	Verify(message, signature, publicKey []byte) (bool, error)
	VerifyWithContext(message, signature, publicKey, context []byte) (bool, error)
}

// KEMAlgorithm is a key-encapsulation mechanism.
type KEMAlgorithm interface {
	ID() string
	Sizes() KEMSizes
	GenerateKeyPair() (KeyPair, error)
	Encapsulate(publicKey []byte) (EncapsulatedSecret, error)
	Decapsulate(ciphertext, secretKey []byte) ([]byte, error)
}
