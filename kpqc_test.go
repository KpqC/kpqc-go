package kpqc_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"kpqc.dev"
)

func ExampleSignatureAlgorithm() {
	algorithm := kpqc.AIMer128f()
	keys, _ := algorithm.GenerateKeyPair()
	message := []byte("release-manifest:v3")
	signature, _ := algorithm.Sign(message, keys.SecretKey)
	valid, _ := algorithm.Verify(message, signature, keys.PublicKey)
	fmt.Println(valid)
	// Output: true
}

func TestSignatureAlgorithms(t *testing.T) {
	message := []byte("KpqC Go")
	context := []byte("release")

	for _, algorithm := range kpqc.SignatureAlgorithms() {
		algorithm := algorithm
		t.Run(algorithm.ID(), func(t *testing.T) {
			keys, err := algorithm.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			sizes := algorithm.Sizes()
			if len(keys.PublicKey) != sizes.PublicKey || len(keys.SecretKey) != sizes.SecretKey {
				t.Fatalf("unexpected key sizes: public=%d secret=%d", len(keys.PublicKey), len(keys.SecretKey))
			}

			signature, err := algorithm.SignWithContext(message, keys.SecretKey, context)
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) != sizes.Signature {
				t.Fatalf("signature has %d bytes, want %d", len(signature), sizes.Signature)
			}
			valid, err := algorithm.VerifyWithContext(message, signature, keys.PublicKey, context)
			if err != nil || !valid {
				t.Fatalf("valid signature rejected: valid=%v err=%v", valid, err)
			}

			altered := bytes.Clone(signature)
			altered[0] ^= 1
			valid, err = algorithm.VerifyWithContext(message, altered, keys.PublicKey, context)
			if err != nil || valid {
				t.Fatalf("altered signature accepted: valid=%v err=%v", valid, err)
			}
			valid, err = algorithm.VerifyWithContext(message, signature, keys.PublicKey, []byte("wrong"))
			if err != nil || valid {
				t.Fatalf("wrong context accepted: valid=%v err=%v", valid, err)
			}
			valid, err = algorithm.Verify(message, []byte{0}, keys.PublicKey)
			if err != nil || valid {
				t.Fatalf("short signature accepted: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestKEMAlgorithms(t *testing.T) {
	for _, algorithm := range kpqc.KEMAlgorithms() {
		algorithm := algorithm
		t.Run(algorithm.ID(), func(t *testing.T) {
			keys, err := algorithm.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			sizes := algorithm.Sizes()
			if len(keys.PublicKey) != sizes.PublicKey || len(keys.SecretKey) != sizes.SecretKey {
				t.Fatalf("unexpected key sizes: public=%d secret=%d", len(keys.PublicKey), len(keys.SecretKey))
			}

			outbound, err := algorithm.Encapsulate(keys.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			inbound, err := algorithm.Decapsulate(outbound.Ciphertext, keys.SecretKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(inbound, outbound.SharedSecret) {
				t.Fatal("decapsulated shared secret does not match")
			}

			altered := bytes.Clone(outbound.Ciphertext)
			altered[0] ^= 1
			replacement, err := algorithm.Decapsulate(altered, keys.SecretKey)
			if strings.HasPrefix(algorithm.ID(), "NTRU+") {
				if err == nil {
					t.Fatal("NTRU+ accepted an altered ciphertext")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(replacement, outbound.SharedSecret) {
					t.Fatal("implicit rejection returned the sender's shared secret")
				}
			}
		})
	}
}

func TestInputValidation(t *testing.T) {
	signature := kpqc.AIMer128f()
	keys, err := signature.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signature.Sign(nil, []byte{0}); !errors.Is(err, kpqc.ErrInvalidSize) {
		t.Fatalf("short secret key error = %v", err)
	}
	if _, err := signature.SignWithContext(nil, keys.SecretKey, make([]byte, 256)); !errors.Is(err, kpqc.ErrContextTooLong) {
		t.Fatalf("long context error = %v", err)
	}

	kem := kpqc.NTRUPlus768()
	if _, err := kem.Encapsulate([]byte{0}); !errors.Is(err, kpqc.ErrInvalidSize) {
		t.Fatalf("short public key error = %v", err)
	}
}
