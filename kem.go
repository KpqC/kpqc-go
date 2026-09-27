package kpqc

type kemBackend struct {
	keyPair     func([]byte, []byte) int
	encapsulate func([]byte, []byte, []byte) int
	decapsulate func([]byte, []byte, []byte) int
}

type kemAlgorithm struct {
	id      string
	sizes   KEMSizes
	backend kemBackend
}

func newKEM(id string, sizes KEMSizes, backend kemBackend) KEMAlgorithm {
	return &kemAlgorithm{id: id, sizes: sizes, backend: backend}
}

func (a *kemAlgorithm) ID() string      { return a.id }
func (a *kemAlgorithm) Sizes() KEMSizes { return a.sizes }

func (a *kemAlgorithm) GenerateKeyPair() (KeyPair, error) {
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

func (a *kemAlgorithm) Encapsulate(publicKey []byte) (EncapsulatedSecret, error) {
	if err := requireSize("public key", publicKey, a.sizes.PublicKey); err != nil {
		return EncapsulatedSecret{}, err
	}
	result := EncapsulatedSecret{
		Ciphertext:   make([]byte, a.sizes.Ciphertext),
		SharedSecret: make([]byte, a.sizes.SharedSecret),
	}
	if status := a.backend.encapsulate(result.Ciphertext, result.SharedSecret, publicKey); status != 0 {
		wipe(result.Ciphertext)
		wipe(result.SharedSecret)
		return EncapsulatedSecret{}, &NativeError{Operation: "encapsulation", Status: status}
	}
	return result, nil
}

func (a *kemAlgorithm) Decapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	if err := requireSize("ciphertext", ciphertext, a.sizes.Ciphertext); err != nil {
		return nil, err
	}
	if err := requireSize("secret key", secretKey, a.sizes.SecretKey); err != nil {
		return nil, err
	}
	sharedSecret := make([]byte, a.sizes.SharedSecret)
	if status := a.backend.decapsulate(sharedSecret, ciphertext, secretKey); status != 0 {
		wipe(sharedSecret)
		return nil, &NativeError{Operation: "decapsulation", Status: status}
	}
	return sharedSecret, nil
}
