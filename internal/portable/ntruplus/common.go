package ntruplus

import (
	"kpqc.dev/internal/portable/ct"
	"kpqc.dev/internal/portable/fips202"
)

type arithmetic interface {
	degree() int
	ntt([]int16)
	inverseNTT([]int16)
	baseInverse([]int16) ([]int16, bool)
	baseMultiply([]int16, []int16) []int16
	baseMultiplyAdd([]int16, []int16, []int16) []int16
}

type randomSource func([]byte) bool

func publicKeyBytes(a arithmetic) int { return 3 * a.degree() / 2 }
func secretKeyBytes(a arithmetic) int { return 3*a.degree() + 32 }

func polyToBytes(a arithmetic, poly []int16) []byte {
	output := make([]byte, publicKeyBytes(a))
	for i := 0; i < a.degree()/2; i++ {
		x, y := poly[2*i], poly[2*i+1]
		if x < 0 {
			x += q
		}
		if y < 0 {
			y += q
		}
		ux, uy := uint16(x), uint16(y)
		output[3*i] = byte(ux)
		output[3*i+1] = byte((ux >> 8) | (uy << 4))
		output[3*i+2] = byte(uy >> 4)
	}
	return output
}

func polyFromBytes(a arithmetic, input []byte) ([]int16, bool) {
	if len(input) != publicKeyBytes(a) {
		return nil, false
	}
	output := make([]int16, a.degree())
	var fail uint32
	for i := 0; i < a.degree()/2; i++ {
		x := (uint16(input[3*i]) | uint16(input[3*i+1])<<8) & 0x0fff
		y := (uint16(input[3*i+1])>>4 | uint16(input[3*i+2])<<4) & 0x0fff
		output[2*i], output[2*i+1] = int16(x), int16(y)
		fail |= uint32(uint16(q)-1) - uint32(x)
		fail |= uint32(uint16(q)-1) - uint32(y)
	}
	return output, fail>>31 == 0
}

func cbd1(a arithmetic, input []byte) []int16 {
	output := make([]int16, a.degree())
	for i := 0; i < a.degree()/8; i++ {
		x, y := input[i], input[i+a.degree()/8]
		for j := 0; j < 8; j++ {
			output[8*i+j] = int16(x&1) - int16(y&1)
			x >>= 1
			y >>= 1
		}
	}
	return output
}

func sotpEncode(a arithmetic, message, pad []byte) []int16 {
	input := append([]byte(nil), pad...)
	for i := 0; i < a.degree()/8; i++ {
		input[i] ^= message[i]
	}
	return cbd1(a, input)
}

func sotpDecode(a arithmetic, poly []int16, pad []byte) ([]byte, bool) {
	message := make([]byte, a.degree()/8)
	var invalid uint32
	for i := 0; i < a.degree()/8; i++ {
		x, y := pad[i], pad[i+a.degree()/8]
		var decoded byte
		for j := 0; j < 8; j++ {
			value := uint16(y&1) + uint16(poly[8*i+j])
			invalid |= uint32(value)
			decoded ^= (byte(value) ^ x) & 1 << j
			x >>= 1
			y >>= 1
		}
		message[i] = decoded
	}
	fail := byte((uint32(0) - (invalid >> 1)) >> 31)
	return message, fail == 0
}

func centeredModThree(value int16) int16 {
	const v int32 = ((1 << 15) + 3/2) / 3
	x := value
	if x < 0 {
		x += q
	}
	x -= (q + 1) / 2
	if x < 0 {
		x += q
	}
	x -= (q - 1) / 2
	rounded := ((v*int32(x) + (1 << 14)) >> 15) * 3
	return narrow(int32(x) - rounded)
}

func domainHash(tag byte, input []byte, outputLen int) []byte {
	prefixed := make([]byte, 1+len(input))
	prefixed[0] = tag
	copy(prefixed[1:], input)
	output := make([]byte, outputLen)
	fips202.Shake256(output, prefixed)
	return output
}

func generate(a arithmetic, seed []byte, constant bool) ([]int16, []int16, bool) {
	bytes := make([]byte, a.degree()/4)
	fips202.Shake256(bytes, seed)
	poly := cbd1(a, bytes)
	for i := range poly {
		poly[i] *= 3
	}
	if constant {
		poly[0]++
	}
	a.ntt(poly)
	inverse, ok := a.baseInverse(poly)
	return poly, inverse, ok
}

func keyPair(a arithmetic, random randomSource) ([]byte, []byte, bool) {
	var f, fInverse []int16
	for {
		seed := make([]byte, 32)
		if !random(seed) {
			return nil, nil, false
		}
		var ok bool
		f, fInverse, ok = generate(a, seed, true)
		if ok {
			break
		}
	}
	var g, gInverse []int16
	for {
		seed := make([]byte, 32)
		if !random(seed) {
			return nil, nil, false
		}
		var ok bool
		g, gInverse, ok = generate(a, seed, false)
		if ok {
			break
		}
	}
	h := a.baseMultiply(g, fInverse)
	hInverse := a.baseMultiply(f, gInverse)
	publicKey := polyToBytes(a, h)
	secretKey := make([]byte, 0, secretKeyBytes(a))
	secretKey = append(secretKey, polyToBytes(a, f)...)
	secretKey = append(secretKey, polyToBytes(a, hInverse)...)
	secretKey = append(secretKey, domainHash(0, publicKey, 32)...)
	return publicKey, secretKey, true
}

func encapsulate(a arithmetic, publicKey []byte, random randomSource) ([]byte, []byte, bool) {
	h, ok := polyFromBytes(a, publicKey)
	if !ok {
		return nil, nil, false
	}
	message := make([]byte, a.degree()/8+32)
	if !random(message[:a.degree()/8]) {
		return nil, nil, false
	}
	copy(message[a.degree()/8:], domainHash(0, publicKey, 32))
	hashed := domainHash(2, message, 32+a.degree()/4)
	rPoly := cbd1(a, hashed[32:])
	a.ntt(rPoly)
	encodedR := polyToBytes(a, rPoly)
	pad := domainHash(1, encodedR, a.degree()/4)
	m := sotpEncode(a, message, pad)
	a.ntt(m)
	ciphertext := polyToBytes(a, a.baseMultiplyAdd(h, rPoly, m))
	return ciphertext, append([]byte(nil), hashed[:32]...), true
}

func decapsulate(a arithmetic, ciphertext, secretKey []byte) ([]byte, bool) {
	polyBytes := publicKeyBytes(a)
	if len(secretKey) != secretKeyBytes(a) {
		return nil, false
	}
	c, ok := polyFromBytes(a, ciphertext)
	if !ok {
		return nil, false
	}
	f, ok := polyFromBytes(a, secretKey[:polyBytes])
	if !ok {
		return nil, false
	}
	hInverse, ok := polyFromBytes(a, secretKey[polyBytes:2*polyBytes])
	if !ok {
		return nil, false
	}
	m1 := a.baseMultiply(c, f)
	a.inverseNTT(m1)
	for i := range m1 {
		m1[i] = centeredModThree(m1[i])
	}
	m2 := append([]int16(nil), m1...)
	a.ntt(m2)
	for i := range c {
		c[i] = narrow(int32(c[i]) - int32(m2[i]))
	}
	r2 := a.baseMultiply(c, hInverse)
	encodedR2 := polyToBytes(a, r2)
	pad := domainHash(1, encodedR2, a.degree()/4)
	decoded, ok := sotpDecode(a, m1, pad)
	if !ok {
		return nil, false
	}
	message := make([]byte, 0, a.degree()/8+32)
	message = append(message, decoded...)
	message = append(message, secretKey[2*polyBytes:]...)
	hashed := domainHash(2, message, 32+a.degree()/4)
	r1 := cbd1(a, hashed[32:])
	a.ntt(r1)
	encodedR1 := polyToBytes(a, r1)
	if ct.Equal(encodedR1, encodedR2) != 1 {
		return nil, false
	}
	return append([]byte(nil), hashed[:32]...), true
}
