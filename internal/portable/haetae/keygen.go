package haetae

import (
	"kpqc.dev/internal/portable/entropy"
	"kpqc.dev/internal/portable/fips202"
)

func generateKeyPair(p params, publicKey, secretKey []byte) int {
	if len(publicKey) != p.publicKeyBytes || len(secretKey) != p.secretKeyBytes {
		return -1
	}
	seed := make([]byte, seedBytes)
	if !entropy.Fill(seed) {
		return -1
	}
	expanded := make([]byte, 2*seedBytes+crhBytes)
	fips202.Shake256(expanded, seed)
	matrixSeed := expanded[:seedBytes]
	secretSeed := expanded[seedBytes : seedBytes+crhBytes]
	key := expanded[seedBytes+crhBytes:]
	matrix := expandMatrix(p, matrixSeed, false)
	var publicRandom polyVec
	if p.mode != 5 {
		publicRandom = expandPublicVector(p, matrixSeed)
	}
	counter := 0
	for {
		first, second := expandSecret(p, secretSeed, counter)
		counter += p.m + p.k
		if p.mode == 5 && float64(secretSingularValue(p, first, second)) > p.gamma*p.gamma*n {
			continue
		}
		transformedFirst := transformVector(first)
		publicVector := multiplyMatrix(matrix, transformedFirst)
		if p.mode == 5 {
			transformedSecond := transformVector(second)
			publicVector = conditionalAddQ(doubleNegateMontgomery(addVectors(convertFromMontgomery(publicVector), transformedSecond)))
		} else {
			publicVector = freezeVector(addVectors(addVectors(inverseTransformVector(publicVector), second), publicRandom))
			var low polyVec
			publicVector, low = publicKeyDecompose(publicVector)
			for i := range second {
				for j := range second[i] {
					second[i][j] -= low[i][j]
				}
			}
			if float64(secretSingularValue(p, first, second)) > p.gamma*p.gamma*n {
				continue
			}
		}
		packedPublic := packPublicKey(p, matrixSeed, publicVector)
		copy(publicKey, packedPublic)
		packedSecret := packSecretKey(p, publicKey, first, second, key)
		copy(secretKey, packedSecret)
		return 0
	}
}
