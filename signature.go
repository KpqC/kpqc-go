package kpqc

import "fmt"

type signatureBackend struct {
	keyPair func([]byte, []byte) int
	sign    func([]byte, *uint64, []byte, []byte, []byte) int
	verify  func([]byte, []byte, []byte, []byte) int
}

type signatureAlgorithm struct {
	id      string
	sizes   SignatureSizes
	backend signatureBackend
}

func newSignature(id string, sizes SignatureSizes, backend signatureBackend) SignatureAlgorithm {
	return &signatureAlgorithm{id: id, sizes: sizes, backend: backend}
}

func (a *signatureAlgorithm) ID() string            { return a.id }
func (a *signatureAlgorithm) Sizes() SignatureSizes { return a.sizes }

func (a *signatureAlgorithm) GenerateKeyPair() (KeyPair, error) {
	result := KeyPair{
		PublicKey: make([]byte, a.sizes.PublicKey),
		SecretKey: make([]byte, a.sizes.SecretKey),
	}
	if status := a.backend.keyPair(result.PublicKey, result.SecretKey); status != 0 {
		wipe(result.PublicKey)
		wipe(result.SecretKey)
		return KeyPair{}, &NativeError{Operation: "key generation", Status: status}
	}
	return result, nil
}

func (a *signatureAlgorithm) Sign(message, secretKey []byte) ([]byte, error) {
	return a.SignWithContext(message, secretKey, nil)
}

func (a *signatureAlgorithm) SignWithContext(message, secretKey, context []byte) ([]byte, error) {
	if err := requireSize("secret key", secretKey, a.sizes.SecretKey); err != nil {
		return nil, err
	}
	if err := requireContext(context); err != nil {
		return nil, err
	}
	signature := make([]byte, a.sizes.Signature)
	var length uint64
	status := a.backend.sign(signature, &length, message, context, secretKey)
	if status != 0 || length != uint64(a.sizes.Signature) {
		wipe(signature)
		if status == 0 {
			status = -1
		}
		return nil, &NativeError{Operation: "signing", Status: status}
	}
	return signature, nil
}

func (a *signatureAlgorithm) Verify(message, signature, publicKey []byte) (bool, error) {
	return a.VerifyWithContext(message, signature, publicKey, nil)
}

func (a *signatureAlgorithm) VerifyWithContext(message, signature, publicKey, context []byte) (bool, error) {
	if err := requireSize("public key", publicKey, a.sizes.PublicKey); err != nil {
		return false, err
	}
	if err := requireContext(context); err != nil {
		return false, err
	}
	if len(signature) != a.sizes.Signature {
		return false, nil
	}
	status := a.backend.verify(signature, message, context, publicKey)
	if status == -2 {
		return false, &NativeError{Operation: "verification", Status: status}
	}
	return status == 0, nil
}

func requireSize(label string, value []byte, expected int) error {
	if len(value) == expected {
		return nil
	}
	return fmt.Errorf("%w: %s must be %d bytes, received %d", ErrInvalidSize, label, expected, len(value))
}

func requireContext(context []byte) error {
	if len(context) <= 255 {
		return nil
	}
	return fmt.Errorf("%w, received %d", ErrContextTooLong, len(context))
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
