package haetae

import (
	"kpqc.dev/internal/portable/ct"
	"kpqc.dev/internal/portable/entropy"
	"kpqc.dev/internal/portable/fips202"
)

func digest256(parts ...[]byte) []byte {
	h := fips202.NewShake256()
	for _, part := range parts {
		h.Absorb(part)
	}
	out := make([]byte, crhBytes)
	h.Squeeze(out)
	return out
}
func prefixContext(context []byte) ([]byte, bool) {
	if len(context) > 255 {
		return nil, false
	}
	return append([]byte{byte(len(context))}, context...), true
}
func decomposeVector(value polyVec) (polyVec, polyVec) {
	high, low := zeroVector(len(value)), zeroVector(len(value))
	for i := range value {
		high[i], low[i] = decomposePolynomial(&value[i])
	}
	return high, low
}
func addNegativeHintModulus(p params, value polyVec) polyVec {
	modulus := (doubleQ - 2) / p.alphaHint
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			if out[i][j] < 0 {
				out[i][j] += modulus
			}
		}
	}
	return out
}

func sign(p params, signature []byte, length *uint64, message, context, secretKey []byte) int {
	if len(signature) != p.signatureBytes || len(secretKey) != p.secretKeyBytes {
		return -1
	}
	prefix, ok := prefixContext(context)
	if !ok {
		return -1
	}
	randomness := make([]byte, seedBytes)
	if !entropy.Fill(randomness) {
		return -1
	}
	matrix, secretFirst, secretSecond, key := unpackSecretKey(p, secretKey)
	publicKey := secretKey[:p.publicKeyBytes]
	digest := digest256(publicKey, prefix, message)
	seed := digest256(key, randomness, digest)
	transformedFirst, transformedSecond := transformVector(secretFirst), transformVector(secretSecond)
	b0Limit := p.b0Squared * uint64(fixedScale*fixedScale)
	b1Limit := p.b1Squared * uint64(fixedScale*fixedScale)
	counter := 0
	for {
		sampled := sampleHyperball(p, seed, counter)
		counter = sampled.nextNonce
		roundedFirst, roundedSecond := roundFixed(sampled.first), roundFixed(sampled.second)
		roundedFirstZero := roundedFirst[0]
		product := inverseTransformVector(multiplyMatrix(matrix, transformVector(roundedFirst)))
		product = addVectors(product, doubleVector(roundedSecond))
		product = freezeVector2Q(recoverCRTVector(product, &roundedFirstZero))
		highBits := hintHighBits(p, product)
		parity := leastSignificantBits(&roundedFirstZero)
		packed := append(packHighBits(p, highBits), packLeastSignificantBits(&parity)...)
		challengeValue := challenge(p, packed, digest[:seedBytes])
		transformedChallenge := transform(challengeValue)
		challengeFirst := zeroVector(p.l)
		challengeFirst[0] = challengeValue
		for i := 1; i < p.l; i++ {
			multiplied := pointwise(&transformedFirst[i-1], &transformedChallenge)
			challengeFirst[i] = inverseTransform(multiplied)
		}
		challengeSecond := inverseTransformVector(multiplyPolynomialVector(transformedSecond, &transformedChallenge))
		signBit := sampled.bit & 1
		first := addFixedSignedInteger(sampled.first, challengeFirst, signBit)
		second := addFixedSignedInteger(sampled.second, challengeSecond, signBit)
		if squaredNorm(first, second) > b1Limit {
			continue
		}
		if sampled.bit&2 != 0 && squaredNorm(doubleMinusFixedVectors(first, sampled.first), doubleMinusFixedVectors(second, sampled.second)) < b0Limit {
			continue
		}
		roundedZ1, roundedZ2 := roundFixed(first), roundFixed(second)
		hintBase := subtractVectors(product, doubleVector(roundedZ2))
		hintBase = hintHighBits(p, freezeVector2Q(hintBase))
		hint := addNegativeHintModulus(p, subtractVectors(highBits, hintBase))
		high, low := decomposeVector(roundedZ1)
		packedSignature, ok := packSignature(p, &challengeValue, low, high, hint)
		if !ok {
			continue
		}
		copy(signature, packedSignature)
		*length = uint64(p.signatureBytes)
		return 0
	}
}

func verify(p params, signature, message, context, publicKey []byte) int {
	if len(publicKey) != p.publicKeyBytes {
		return 1
	}
	prefix, ok := prefixContext(context)
	if !ok {
		return 1
	}
	decoded, ok := unpackSignature(p, signature)
	if !ok {
		return 1
	}
	matrix := unpackPublicKey(p, publicKey)
	first := zeroVector(p.l)
	for i := range first {
		first[i] = composePolynomial(&decoded.highBits[i], &decoded.lowBits[i])
	}
	norm := vectorSquaredNorm(first)
	difference := subtract(&first[0], &decoded.challenge)
	parity := leastSignificantBits(&difference)
	product := inverseTransformVector(multiplyMatrix(matrix, transformVector(first)))
	product = freezeVector2Q(recoverCRTVector(product, &parity))
	recoveredHigh := normalizeHint(p, addVectors(hintHighBits(p, product), decoded.hint))
	second := subtractVectors(multiplyByAlpha(p, recoveredHigh), product)
	second[0] = add(&second[0], &parity)
	second = divideVectorBy2(reduceVector2Q(second))
	norm += vectorSquaredNorm(second)
	if norm > p.b2Squared {
		return 1
	}
	packed := append(packHighBits(p, recoveredHigh), packLeastSignificantBits(&parity)...)
	digest := digest256(publicKey, prefix, message)
	expected := challenge(p, packed, digest[:seedBytes])
	expectedBytes := make([]byte, n*4)
	challengeBytes := make([]byte, n*4)
	for i := 0; i < n; i++ {
		for j := 0; j < 4; j++ {
			expectedBytes[4*i+j] = byte(uint32(expected[i]) >> uint(8*j))
			challengeBytes[4*i+j] = byte(uint32(decoded.challenge[i]) >> uint(8*j))
		}
	}
	if ct.Equal(expectedBytes, challengeBytes) == 1 {
		return 0
	}
	return 1
}

func KeyPair2(publicKey, secretKey []byte) int { return generateKeyPair(mode2, publicKey, secretKey) }
func Sign2(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(mode2, signature, length, message, context, secretKey)
}
func Verify2(signature, message, context, publicKey []byte) int {
	return verify(mode2, signature, message, context, publicKey)
}
func KeyPair3(publicKey, secretKey []byte) int { return generateKeyPair(mode3, publicKey, secretKey) }
func Sign3(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(mode3, signature, length, message, context, secretKey)
}
func Verify3(signature, message, context, publicKey []byte) int {
	return verify(mode3, signature, message, context, publicKey)
}
func KeyPair5(publicKey, secretKey []byte) int { return generateKeyPair(mode5, publicKey, secretKey) }
func Sign5(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(mode5, signature, length, message, context, secretKey)
}
func Verify5(signature, message, context, publicKey []byte) int {
	return verify(mode5, signature, message, context, publicKey)
}
