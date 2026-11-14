// Package ntruplus contains the dependency-free Go implementation of NTRU+.
package ntruplus

import "kpqc.dev/internal/portable/entropy"

type parameters struct {
	arithmetic arithmetic
	publicKey  int
	secretKey  int
	ciphertext int
}

var (
	params768  = parameters{arithmetic768{}, 1152, 2336, 1152}
	params864  = parameters{arithmetic864{}, 1296, 2624, 1296}
	params1152 = parameters{arithmetic1152{}, 1728, 3488, 1728}
)

func keyPairFor(params parameters, publicKey, secretKey []byte) int {
	if len(publicKey) != params.publicKey || len(secretKey) != params.secretKey {
		return -1
	}
	pk, sk, ok := keyPair(params.arithmetic, entropy.Fill)
	if !ok {
		return -1
	}
	copy(publicKey, pk)
	copy(secretKey, sk)
	return 0
}

func encapsulateFor(params parameters, ciphertext, sharedSecret, publicKey []byte) int {
	if len(ciphertext) != params.ciphertext || len(sharedSecret) != 32 || len(publicKey) != params.publicKey {
		return -1
	}
	ct, ss, ok := encapsulate(params.arithmetic, publicKey, entropy.Fill)
	if !ok {
		return -1
	}
	copy(ciphertext, ct)
	copy(sharedSecret, ss)
	return 0
}

func decapsulateFor(params parameters, sharedSecret, ciphertext, secretKey []byte) int {
	if len(sharedSecret) != 32 || len(ciphertext) != params.ciphertext || len(secretKey) != params.secretKey {
		return -1
	}
	ss, ok := decapsulate(params.arithmetic, ciphertext, secretKey)
	if !ok {
		return -1
	}
	copy(sharedSecret, ss)
	return 0
}

func KeyPair768(publicKey, secretKey []byte) int { return keyPairFor(params768, publicKey, secretKey) }
func Encapsulate768(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulateFor(params768, ciphertext, sharedSecret, publicKey)
}
func Decapsulate768(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulateFor(params768, sharedSecret, ciphertext, secretKey)
}

func KeyPair864(publicKey, secretKey []byte) int { return keyPairFor(params864, publicKey, secretKey) }
func Encapsulate864(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulateFor(params864, ciphertext, sharedSecret, publicKey)
}
func Decapsulate864(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulateFor(params864, sharedSecret, ciphertext, secretKey)
}

func KeyPair1152(publicKey, secretKey []byte) int {
	return keyPairFor(params1152, publicKey, secretKey)
}
func Encapsulate1152(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulateFor(params1152, ciphertext, sharedSecret, publicKey)
}
func Decapsulate1152(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulateFor(params1152, sharedSecret, ciphertext, secretKey)
}
