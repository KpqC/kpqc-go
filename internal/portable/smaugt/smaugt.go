// Package smaugt contains the dependency-free Go implementation of SMAUG-T.
package smaugt

import (
	"encoding/binary"

	"kpqc.dev/internal/portable/ct"
	"kpqc.dev/internal/portable/entropy"
	"kpqc.dev/internal/portable/fips202"
)

const (
	n            = 256
	cryptoBytes  = 32
	tBytes       = 32
	pkSeedBytes  = 32
	hwtSeedBytes = 616
)

type poly [n]int16
type polyVec []poly
type matrix []polyVec

type params struct {
	k             int
	logQ          int
	logP          int
	logPPrime     int
	cbdSeedBytes  int
	messageBytes  int
	hammingWeight int16
	timer         bool
}

func (p params) publicKeyBytes() int    { return pkSeedBytes + p.k*p.logQ*n/8 }
func (p params) pkeSecretKeyBytes() int { return p.k * n / 4 }
func (p params) secretKeyBytes() int    { return p.pkeSecretKeyBytes() + tBytes + p.publicKeyBytes() }
func (p params) ciphertextBytes() int   { return p.k*p.logP*n/8 + p.logPPrime*n/8 }

var (
	mode1 = params{2, 10, 8, 5, 96, 32, 70, false}
	mode3 = params{3, 11, 9, 4, 64, 32, 88, false}
	mode5 = params{4, 11, 9, 7, 128, 32, 87, false}
	modeT = params{2, 10, 8, 3, 96, 16, 70, true}
)

func zeroPolyVec(k int) polyVec { return make(polyVec, k) }

func packPoly(output []byte, polynomial *poly, bits int, scaled bool) {
	clear(output)
	mask := uint16(1<<bits) - 1
	shift := 16 - bits
	bitPosition := 0
	for _, coefficient := range polynomial {
		var value uint16
		if scaled {
			value = uint16(coefficient>>shift) & mask
		} else {
			value = uint16(coefficient) & mask
		}
		for bit := 0; bit < bits; bit++ {
			output[bitPosition>>3] |= byte((value>>bit)&1) << (bitPosition & 7)
			bitPosition++
		}
	}
}

func unpackPoly(polynomial *poly, input []byte, bits int, scaled bool) {
	shift := 16 - bits
	bitPosition := 0
	for i := range polynomial {
		var value uint16
		for bit := 0; bit < bits; bit++ {
			value |= uint16((input[bitPosition>>3]>>(bitPosition&7))&1) << bit
			bitPosition++
		}
		if scaled {
			polynomial[i] = int16(value << shift)
		} else {
			polynomial[i] = int16(value)
		}
	}
}

func packSecret(output []byte, secret polyVec) {
	for p := range secret {
		bytes := output[p*(n/4) : (p+1)*(n/4)]
		for i := range bytes {
			var packed byte
			for j := 0; j < 4; j++ {
				packed |= (byte(1-secret[p][4*i+j]) & 3) << (2 * j)
			}
			bytes[i] = packed
		}
	}
}

func unpackSecret(p params, input []byte) polyVec {
	secret := zeroPolyVec(p.k)
	for polynomial := range secret {
		bytes := input[polynomial*(n/4) : (polynomial+1)*(n/4)]
		for i, value := range bytes {
			for j := 0; j < 4; j++ {
				secret[polynomial][4*i+j] = 1 - int16((value>>(2*j))&3)
			}
		}
	}
	return secret
}

func packVector(output []byte, vector polyVec, bits int, scaled bool) {
	polynomialBytes := bits * n / 8
	for i := range vector {
		packPoly(output[i*polynomialBytes:(i+1)*polynomialBytes], &vector[i], bits, scaled)
	}
}

func unpackVector(p params, input []byte, bits int, scaled bool) polyVec {
	polynomialBytes := bits * n / 8
	vector := zeroPolyVec(p.k)
	for i := range vector {
		unpackPoly(&vector[i], input[i*polynomialBytes:(i+1)*polynomialBytes], bits, scaled)
	}
	return vector
}

func multiplyAccumulate(output, left, right *poly) {
	for i, a := range left {
		for j, b := range right {
			product := uint16(a) * uint16(b)
			index := i + j
			target := &output[index&(n-1)]
			if index < n {
				*target = int16(uint16(*target) + product)
			} else {
				*target = int16(uint16(*target) - product)
			}
		}
	}
}

func vectorMultiply(left, right polyVec) poly {
	var output poly
	for i := range left {
		multiplyAccumulate(&output, &left[i], &right[i])
	}
	return output
}

func shiftLeft(value int16, shift int) int16 { return int16(uint16(value) << shift) }

func expandA(p params, seed *[pkSeedBytes]byte) matrix {
	result := make(matrix, p.k)
	for i := range result {
		result[i] = zeroPolyVec(p.k)
	}
	var extended [pkSeedBytes + 2]byte
	copy(extended[:], seed[:])
	bytes := make([]byte, p.logQ*n/8)
	for i := range result {
		for j := range result[i] {
			extended[pkSeedBytes], extended[pkSeedBytes+1] = byte(i), byte(j)
			fips202.Shake128(bytes, extended[:])
			unpackPoly(&result[i][j], bytes, p.logQ, true)
		}
	}
	return result
}

func sparseCBD(p params, bytes []byte) poly {
	var output poly
	switch p.cbdSeedBytes {
	case 96:
		for block := 0; block < len(bytes)/3; block++ {
			value := uint32(bytes[3*block]) | uint32(bytes[3*block+1])<<8 | uint32(bytes[3*block+2])<<16
			present := value & 0x00249249
			present &= (value >> 1) & 0x00249249
			signs := (value >> 2) & 0x00249249
			for i := 0; i < 8; i++ {
				magnitude := int16((present >> (3 * i)) & 1)
				if (signs>>(3*i))&1 == 0 {
					output[8*block+i] = magnitude
				} else {
					output[8*block+i] = -magnitude
				}
			}
		}
	case 64:
		for block := 0; block < len(bytes)/4; block++ {
			value := binary.LittleEndian.Uint32(bytes[4*block:])
			for i := 0; i < 16; i++ {
				output[16*block+i] = int16((value>>(2*i))&1) - int16((value>>(2*i+1))&1)
			}
		}
	case 128:
		for block := 0; block < len(bytes)/4; block++ {
			value := binary.LittleEndian.Uint32(bytes[4*block:])
			present := value & 0x11111111
			present |= (value >> 1) & 0x11111111
			present &= (value >> 2) & 0x11111111
			signs := (value >> 3) & 0x11111111
			for i := 0; i < 8; i++ {
				magnitude := int16((present >> (4 * i)) & 1)
				if (signs>>(4*i))&1 == 0 {
					output[8*block+i] = magnitude
				} else {
					output[8*block+i] = -magnitude
				}
			}
		}
	default:
		panic("smaugt: unsupported CBD size")
	}
	return output
}

func expandR(p params, seed []byte) polyVec {
	output := zeroPolyVec(p.k)
	var extended [33]byte
	copy(extended[:32], seed[:32])
	bytes := make([]byte, p.cbdSeedBytes)
	for i := range output {
		extended[32] = byte(i)
		fips202.Shake256(bytes, extended[:])
		output[i] = sparseCBD(p, bytes)
	}
	return output
}

func gaussianPoly(p params, seed *[33]byte) poly {
	var bytes [320]byte
	fips202.Shake256(bytes[:], seed[:])
	var random [40]uint64
	for block := 0; block < 4; block++ {
		for column := 0; column < 10; column++ {
			var lane [8]byte
			for row := 0; row < 8; row++ {
				lane[row] = bytes[block*80+row*10+column]
			}
			random[block*10+column] = binary.LittleEndian.Uint64(lane[:])
		}
	}
	var output poly
	for block := 0; block < 4; block++ {
		x := random[block*10 : block*10+10]
		low := (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & ^x[8]) |
			(x[0] & x[3] & x[4] & x[5] & x[6] & x[8]) |
			(x[1] & x[3] & x[4] & x[5] & x[6] & x[8]) |
			(x[2] & x[3] & x[4] & x[5] & x[6] & x[8]) |
			(^x[2] & ^x[3] & ^x[6] & x[8]) |
			(^x[1] & ^x[3] & ^x[6] & x[8]) |
			(x[6] & x[7] & ^x[8]) | (^x[5] & ^x[6] & x[8]) |
			(^x[4] & ^x[6] & x[8]) | (^x[7] & x[8])
		high := (x[1] & x[2] & x[4] & x[5] & x[7] & x[8]) |
			(x[3] & x[4] & x[5] & x[7] & x[8]) | (x[6] & x[7] & x[8])
		for bit := 0; bit < 64; bit++ {
			magnitude := int16((low>>bit)&1 | ((high>>bit)&1)<<1)
			if (x[9]>>bit)&1 != 0 {
				magnitude = -magnitude
			}
			output[block*64+bit] = shiftLeft(magnitude, 16-p.logQ)
		}
	}
	return output
}

func gaussianVector(p params, seed *[32]byte) polyVec {
	output := zeroPolyVec(p.k)
	var extended [33]byte
	copy(extended[:32], seed[:])
	for i := range output {
		extended[32] = byte(p.k * i)
		output[i] = gaussianPoly(p, &extended)
	}
	return output
}

func hwt(p params, seed *[34]byte) (poly, bool) {
	sponge := fips202.NewShake256()
	sponge.Absorb(seed[:])
	var bytes [hwtSeedBytes]byte
	sponge.Squeeze(bytes[:])
	var random [hwtSeedBytes / 2]uint16
	for i := range random {
		random[i] = binary.LittleEndian.Uint16(bytes[2*i:])
	}
	var shuffled [n]int16
	extra := n
	for index := range shuffled {
		rangeSize := uint16(n - index)
		threshold := uint16((uint32(1) << 16) % uint32(rangeSize))
		product := uint32(random[index]) * uint32(rangeSize)
		for uint16(product) < threshold {
			if extra >= len(random) {
				return poly{}, false
			}
			product = uint32(random[extra]) * uint32(rangeSize)
			extra++
		}
		shuffled[index] = int16(product >> 16)
	}
	var signs [n / 4]byte
	sponge.Squeeze(signs[:])
	var output poly
	cutoff := int16(n) - p.hammingWeight
	for index := 0; index < n; index++ {
		selected := (shuffled[index] - cutoff) >> 15
		cutoff += selected
		magnitude := int16(1) + selected
		signByte := signs[((index>>7)<<4)+(index&0x0f)]
		sign := int16((signByte >> ((index >> 4) & 7)) & 1)
		output[index] = -magnitude & ((sign << 1) - 1)
	}
	return output, true
}

func expandSecret(p params, seed *[32]byte) polyVec {
	output := zeroPolyVec(p.k)
	for i := range output {
		for retry := 0; ; retry++ {
			var extended [34]byte
			copy(extended[:32], seed[:])
			extended[32], extended[33] = byte(i*p.k), byte(retry)
			if sample, ok := hwt(p, &extended); ok {
				output[i] = sample
				break
			}
		}
	}
	return output
}

func matrixVectorSubtract(p params, output polyVec, m matrix, vector polyVec) {
	shift := 16 - p.logQ
	for row := range m {
		lowered := zeroPolyVec(p.k)
		for i := range m[row] {
			for j, coefficient := range m[row][i] {
				lowered[i][j] = coefficient >> shift
			}
		}
		product := vectorMultiply(lowered, vector)
		for i, value := range product {
			output[row][i] = int16(uint16(output[row][i]) - uint16(shiftLeft(value, shift)))
		}
	}
}

func transposeMatrixVector(p params, m matrix, vector polyVec) polyVec {
	shift := 16 - p.logQ
	output := zeroPolyVec(p.k)
	for column := 0; column < p.k; column++ {
		lowered := zeroPolyVec(p.k)
		for row := 0; row < p.k; row++ {
			for i, coefficient := range m[row][column] {
				lowered[row][i] = coefficient >> shift
			}
		}
		product := vectorMultiply(lowered, vector)
		for i, value := range product {
			output[column][i] = shiftLeft(value, shift)
		}
	}
	return output
}

func vectorMultiplyAdd(output *poly, left, right polyVec, shift int) {
	lowered := make(polyVec, len(left))
	for p := range left {
		for i, coefficient := range left[p] {
			lowered[p][i] = coefficient >> shift
		}
	}
	product := vectorMultiply(lowered, right)
	for i, value := range product {
		output[i] = int16(uint16(output[i]) + uint16(shiftLeft(value, shift)))
	}
}

func keyPairInternal(p params, publicKey, secretKey []byte, rejectionKey, seed *[32]byte) {
	expanded := fips202.SHA3512(seed[:])
	var secretSeed, matrixSeed [32]byte
	copy(secretSeed[:], expanded[:32])
	copy(matrixSeed[:], expanded[32:])
	secret := expandSecret(p, &secretSeed)
	m := expandA(p, &matrixSeed)
	publicVector := gaussianVector(p, &secretSeed)
	matrixVectorSubtract(p, publicVector, m, secret)
	copy(publicKey[:32], matrixSeed[:])
	packVector(publicKey[32:], publicVector, p.logQ, true)
	pkeBytes := p.pkeSecretKeyBytes()
	packSecret(secretKey[:pkeBytes], secret)
	copy(secretKey[pkeBytes:pkeBytes+32], rejectionKey[:])
	copy(secretKey[pkeBytes+32:], publicKey)
}

func unpackPublic(p params, publicKey []byte) (matrix, polyVec) {
	var matrixSeed [32]byte
	copy(matrixSeed[:], publicKey[:32])
	return expandA(p, &matrixSeed), unpackVector(p, publicKey[32:], p.logQ, true)
}

func encodeMessage(p params, message []byte) poly {
	var output poly
	if p.timer {
		for i := 0; i < 128; i++ {
			var value int16
			if (message[i>>3]>>(i&7))&1 != 0 {
				value = 32767
			}
			output[i], output[i+128] = value, value
		}
	} else {
		for i := 0; i < n; i++ {
			if (message[i>>3]>>(i&7))&1 != 0 {
				output[i] = -32768
			}
		}
	}
	return output
}

func roundingConstants(bits int) (uint16, uint16) {
	shift := 16 - bits
	return 1 << (shift - 1), ^uint16(0) << shift
}

func indcpaEncrypt(p params, output, publicKey, message, seed []byte) {
	m, publicVector := unpackPublic(p, publicKey)
	ephemeral := expandR(p, seed)
	c1 := transposeMatrixVector(p, m, ephemeral)
	add1, mask1 := roundingConstants(p.logP)
	shift1 := 16 - p.logP
	for polynomial := range c1 {
		for i := range c1[polynomial] {
			c1[polynomial][i] = int16((uint16(c1[polynomial][i])+add1)&mask1) >> shift1
		}
	}
	c2 := encodeMessage(p, message)
	vectorMultiplyAdd(&c2, publicVector, ephemeral, 16-p.logQ)
	add2, mask2 := roundingConstants(p.logPPrime)
	shift2 := 16 - p.logPPrime
	for i := range c2 {
		c2[i] = int16((uint16(c2[i])+add2)&mask2) >> shift2
	}
	c1Bytes := p.k * p.logP * n / 8
	packVector(output[:c1Bytes], c1, p.logP, false)
	packPoly(output[c1Bytes:], &c2, p.logPPrime, false)
}

func flipAbs(value int16) uint16 {
	difference := int16(uint16(value) - 32767)
	mask := difference >> 15
	return uint16((difference + mask) ^ mask)
}

func decodeMessage(p params, polynomial *poly) []byte {
	message := make([]byte, p.messageBytes)
	if p.timer {
		for i := 0; i < 128; i++ {
			value := (flipAbs(polynomial[i]) + flipAbs(polynomial[i+128]) - 32767) >> 15
			message[i>>3] |= byte(value) << (i & 7)
		}
	} else {
		for i := 0; i < n; i++ {
			value := int16(uint16(polynomial[i]) + 0x4000)
			message[i>>3] |= byte((value>>15)&1) << (i & 7)
		}
	}
	return message
}

func indcpaDecrypt(p params, secretKey, ciphertext []byte) []byte {
	secret := unpackSecret(p, secretKey)
	c1Bytes := p.k * p.logP * n / 8
	c1 := unpackVector(p, ciphertext[:c1Bytes], p.logP, false)
	var delta poly
	unpackPoly(&delta, ciphertext[c1Bytes:], p.logPPrime, false)
	for polynomial := range c1 {
		for i := range c1[polynomial] {
			c1[polynomial][i] = shiftLeft(c1[polynomial][i], 16-p.logP)
		}
	}
	for i := range delta {
		delta[i] = shiftLeft(delta[i], 16-p.logPPrime)
	}
	vectorMultiplyAdd(&delta, c1, secret, 16-p.logP)
	return decodeMessage(p, &delta)
}

func hashG(first, second []byte) [64]byte {
	sponge := fips202.NewShake256()
	sponge.Absorb(first)
	sponge.Absorb(second)
	var output [64]byte
	sponge.Squeeze(output[:])
	return output
}

func keyPair(p params, publicKey, secretKey []byte) int {
	if len(publicKey) != p.publicKeyBytes() || len(secretKey) != p.secretKeyBytes() {
		return -1
	}
	var rejectionKey, seed [32]byte
	if !entropy.Fill(rejectionKey[:]) || !entropy.Fill(seed[:]) {
		return -1
	}
	keyPairInternal(p, publicKey, secretKey, &rejectionKey, &seed)
	return 0
}

func encapsulate(p params, ciphertext, sharedSecret, publicKey []byte) int {
	if len(ciphertext) != p.ciphertextBytes() || len(sharedSecret) != cryptoBytes || len(publicKey) != p.publicKeyBytes() {
		return -1
	}
	message := make([]byte, p.messageBytes)
	if !entropy.Fill(message) {
		return -1
	}
	publicHash := fips202.SHA3256(publicKey)
	material := hashG(message, publicHash[:])
	indcpaEncrypt(p, ciphertext, publicKey, message, material[:32])
	copy(sharedSecret, material[32:])
	return 0
}

func decapsulate(p params, sharedSecret, ciphertext, secretKey []byte) int {
	if len(sharedSecret) != cryptoBytes || len(ciphertext) != p.ciphertextBytes() || len(secretKey) != p.secretKeyBytes() {
		return -1
	}
	pkeBytes := p.pkeSecretKeyBytes()
	publicKey := secretKey[pkeBytes+tBytes:]
	message := indcpaDecrypt(p, secretKey[:pkeBytes], ciphertext)
	publicHash := fips202.SHA3256(publicKey)
	validMaterial := hashG(message, publicHash[:])
	expected := make([]byte, p.ciphertextBytes())
	indcpaEncrypt(p, expected, publicKey, message, validMaterial[:32])
	ciphertextHash := fips202.SHA3256(ciphertext)
	fallbackMaterial := hashG(secretKey[pkeBytes:pkeBytes+tBytes], ciphertextHash[:])
	ct.Select(sharedSecret, fallbackMaterial[32:], validMaterial[32:], ct.Equal(ciphertext, expected))
	return 0
}

func KeyPair128(publicKey, secretKey []byte) int { return keyPair(mode1, publicKey, secretKey) }
func Encapsulate128(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulate(mode1, ciphertext, sharedSecret, publicKey)
}
func Decapsulate128(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulate(mode1, sharedSecret, ciphertext, secretKey)
}

func KeyPair192(publicKey, secretKey []byte) int { return keyPair(mode3, publicKey, secretKey) }
func Encapsulate192(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulate(mode3, ciphertext, sharedSecret, publicKey)
}
func Decapsulate192(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulate(mode3, sharedSecret, ciphertext, secretKey)
}

func KeyPair256(publicKey, secretKey []byte) int { return keyPair(mode5, publicKey, secretKey) }
func Encapsulate256(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulate(mode5, ciphertext, sharedSecret, publicKey)
}
func Decapsulate256(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulate(mode5, sharedSecret, ciphertext, secretKey)
}

func KeyPairTiMER(publicKey, secretKey []byte) int { return keyPair(modeT, publicKey, secretKey) }
func EncapsulateTiMER(ciphertext, sharedSecret, publicKey []byte) int {
	return encapsulate(modeT, ciphertext, sharedSecret, publicKey)
}
func DecapsulateTiMER(sharedSecret, ciphertext, secretKey []byte) int {
	return decapsulate(modeT, sharedSecret, ciphertext, secretKey)
}
