package haetae

import (
	"encoding/binary"

	"kpqc.dev/internal/portable/fips202"
)

func add(left, right *polynomial) polynomial {
	var out polynomial
	for i := range out {
		out[i] = left[i] + right[i]
	}
	return out
}
func subtract(left, right *polynomial) polynomial {
	var out polynomial
	for i := range out {
		out[i] = left[i] - right[i]
	}
	return out
}
func pointwise(left, right *polynomial) polynomial {
	var out polynomial
	for i := range out {
		out[i] = montgomeryReduce(int64(left[i]) * int64(right[i]))
	}
	return out
}
func pointwiseAccumulate(left, right polyVec) polynomial {
	var out polynomial
	for j := range left {
		for i := range out {
			out[i] += montgomeryReduce(int64(left[j][i]) * int64(right[j][i]))
		}
	}
	return out
}
func transform(value polynomial) polynomial        { ntt(&value); return value }
func inverseTransform(value polynomial) polynomial { inverseNTT(&value); return value }
func transformVector(value polyVec) polyVec {
	out := make(polyVec, len(value))
	for i := range value {
		out[i] = transform(value[i])
	}
	return out
}
func inverseTransformVector(value polyVec) polyVec {
	out := make(polyVec, len(value))
	for i := range value {
		out[i] = inverseTransform(value[i])
	}
	return out
}
func freezePolynomial(value polynomial) polynomial {
	for i := range value {
		value[i] = freeze(value[i])
	}
	return value
}
func freezePolynomial2Q(value polynomial) polynomial {
	for i := range value {
		value[i] = freeze2Q(value[i])
	}
	return value
}
func centeredPolynomial2Q(value polynomial) polynomial {
	for i := range value {
		value[i] = centeredMod2Q(value[i])
	}
	return value
}

func decomposePolynomial(value *polynomial) (polynomial, polynomial) {
	var high, low polynomial
	for i := range value {
		high[i], low[i] = decomposeZ1(value[i])
	}
	return high, low
}
func composePolynomial(high, low *polynomial) polynomial {
	var out polynomial
	for i := range out {
		out[i] = high[i]*256 + low[i]
	}
	return out
}
func leastSignificantBits(value *polynomial) polynomial {
	var out polynomial
	for i := range out {
		out[i] = value[i] & 1
	}
	return out
}
func fromCRT(modQ *polynomial, mod2 *polynomial) polynomial {
	var out polynomial
	for i := range out {
		parity := int32(0)
		if mod2 != nil {
			parity = mod2[i]
		}
		out[i] = modQ[i] + (q & -((modQ[i] ^ parity) & 1))
	}
	return out
}

func stream(bits int, seed []byte, nonce int) *fips202.Shake {
	var h *fips202.Shake
	if bits == 128 {
		h = fips202.NewShake128()
	} else {
		h = fips202.NewShake256()
	}
	h.Absorb(seed)
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(nonce))
	h.Absorb(b[:])
	return h
}
func sampleUniform(seed []byte, nonce int) polynomial {
	var out polynomial
	h := stream(128, seed, nonce)
	count := 0
	var bytes [168]byte
	for count < n {
		h.Squeeze(bytes[:])
		for offset := 0; offset+1 < len(bytes) && count < n; offset += 2 {
			candidate := int32(binary.LittleEndian.Uint16(bytes[offset:]))
			if candidate < q {
				out[count] = candidate
				count++
			}
		}
	}
	return out
}
func centeredMod3(value int) int32 {
	remainder := value % 3
	if remainder == 2 {
		return -1
	}
	return int32(remainder)
}
func sampleEta(seed []byte, nonce int) polynomial {
	var out polynomial
	h := stream(256, seed, nonce)
	count := 0
	var bytes [136]byte
	for count < n {
		h.Squeeze(bytes[:])
		for _, b := range bytes {
			if b >= 243 {
				continue
			}
			value := int(b)
			for digit := 0; digit < 5 && count < n; digit++ {
				out[count] = centeredMod3(value)
				count++
				value /= 3
			}
			if count == n {
				break
			}
		}
	}
	return out
}

func expandMatrix(p params, seed []byte, includeFirst bool) polyMatrix {
	matrix := make(polyMatrix, p.k)
	for row := range matrix {
		matrix[row] = zeroVector(p.m)
		offset := 0
		if includeFirst {
			matrix[row] = zeroVector(p.l)
			offset = 1
		}
		for column := 0; column < p.m; column++ {
			matrix[row][column+offset] = sampleUniform(seed, (row<<8)+column)
		}
	}
	return matrix
}
func expandPublicVector(p params, seed []byte) polyVec {
	nonce := (p.k << 8) + p.m
	out := zeroVector(p.k)
	for i := range out {
		out[i] = sampleUniform(seed, nonce)
		nonce++
	}
	return out
}
func expandSecret(p params, seed []byte, nonce int) (polyVec, polyVec) {
	first, second := zeroVector(p.m), zeroVector(p.k)
	for i := range first {
		first[i] = sampleEta(seed, nonce)
		nonce++
	}
	for i := range second {
		second[i] = sampleEta(seed, nonce)
		nonce++
	}
	return first, second
}
func multiplyMatrix(matrix polyMatrix, input polyVec) polyVec {
	out := zeroVector(len(matrix))
	for i := range matrix {
		out[i] = pointwiseAccumulate(matrix[i], input)
	}
	return out
}
func addVectors(left, right polyVec) polyVec {
	out := zeroVector(len(left))
	for i := range out {
		out[i] = add(&left[i], &right[i])
	}
	return out
}
func subtractVectors(left, right polyVec) polyVec {
	out := zeroVector(len(left))
	for i := range out {
		out[i] = subtract(&left[i], &right[i])
	}
	return out
}
func doubleVector(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] *= 2
		}
	}
	return out
}
func negateVector(value polyVec, bit int32) polyVec {
	factor := int32(1) - 2*bit
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] *= factor
		}
	}
	return out
}
func publicKeyDecompose(value polyVec) (polyVec, polyVec) {
	high, low := zeroVector(len(value)), zeroVector(len(value))
	for i := range value {
		for j := range value[i] {
			high[i][j], low[i][j] = decomposePublicKey(value[i][j])
		}
	}
	return high, low
}
func hintHighBits(p params, value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] = decomposeHint(out[i][j], p.alphaHint, p.logAlphaHint)
		}
	}
	return out
}
func vectorSquaredNorm(value polyVec) uint64 { return squaredNorm(value) }

func challenge(p params, packed, digest []byte) polynomial {
	var out polynomial
	h := fips202.NewShake256()
	h.Absorb(packed)
	h.Absorb(digest)
	if p.mode == 5 {
		var bytes [seedBytes]byte
		h.Squeeze(bytes[:])
		weight := 0
		for _, b := range bytes {
			for bit := 0; bit < 8; bit++ {
				weight += int((b >> bit) & 1)
			}
		}
		mask := byte(0)
		if weight < 128 {
			mask = 0
		} else if weight > 128 {
			mask = 0xff
		} else {
			mask = byte(-int8(bytes[0] & 1))
		}
		for i := 0; i < n; i++ {
			out[i] = int32(((bytes[i>>3] ^ mask) >> (i & 7)) & 1)
		}
		return out
	}
	random := make([]byte, 136)
	h.Squeeze(random)
	position := 0
	for i := n - p.tau; i < n; i++ {
		selected := 0
		for {
			if position == len(random) {
				h.Squeeze(random)
				position = 0
			}
			selected = int(random[position])
			position++
			if selected <= i {
				break
			}
		}
		out[i] = out[selected]
		out[selected] = 1
	}
	return out
}
func recoverCRTVector(modQ polyVec, firstMod2 *polynomial) polyVec {
	out := zeroVector(len(modQ))
	for i := range out {
		var mod2 *polynomial
		if i == 0 {
			mod2 = firstMod2
		}
		out[i] = fromCRT(&modQ[i], mod2)
	}
	return out
}
func reduceVector2Q(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		out[i] = centeredPolynomial2Q(out[i])
	}
	return out
}
func freezeVector(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		out[i] = freezePolynomial(out[i])
	}
	return out
}
func freezeVector2Q(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		out[i] = freezePolynomial2Q(out[i])
	}
	return out
}
func multiplyByAlpha(p params, value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] *= p.alphaHint
		}
	}
	return out
}
func divideVectorBy2(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] >>= 1
		}
	}
	return out
}
func normalizeHint(p params, value polyVec) polyVec {
	modulus := (doubleQ - 2) / p.alphaHint
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] %= modulus
			if out[i][j] < 0 {
				out[i][j] += modulus
			}
		}
	}
	return out
}
func multiplyPolynomialVector(value polyVec, factor *polynomial) polyVec {
	out := zeroVector(len(value))
	for i := range out {
		out[i] = pointwise(&value[i], factor)
	}
	return out
}
func convertFromMontgomery(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] = montgomeryReduce(int64(out[i][j]) * 4214)
		}
	}
	return out
}
func doubleNegateMontgomery(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] = montgomeryReduce(int64(out[i][j]) * -28642)
		}
	}
	return out
}
func conditionalAddQ(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			if out[i][j] < 0 {
				out[i][j] += q
			}
		}
	}
	return out
}
