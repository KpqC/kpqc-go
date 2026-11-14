package haetae

func packBits(values *polynomial, bits int) []byte {
	out := make([]byte, n*bits/8)
	accumulator, available, offset := uint32(0), 0, 0
	for _, coefficient := range values {
		accumulator |= uint32(coefficient) << available
		available += bits
		for available >= 8 {
			out[offset] = byte(accumulator)
			offset++
			accumulator >>= 8
			available -= 8
		}
	}
	return out
}
func unpackBits(bytes []byte, bits int) polynomial {
	var out polynomial
	accumulator, available, offset := uint32(0), 0, 0
	mask := uint32(1<<bits) - 1
	for i := range out {
		for available < bits {
			accumulator |= uint32(bytes[offset]) << available
			offset++
			available += 8
		}
		out[i] = int32(accumulator & mask)
		accumulator >>= bits
		available -= bits
	}
	return out
}
func packPolynomialQ(p params, value *polynomial) []byte {
	bits := 15
	if p.mode == 5 {
		bits = 16
	}
	return packBits(value, bits)
}
func unpackPolynomialQ(p params, value []byte) polynomial {
	bits := 15
	if p.mode == 5 {
		bits = 16
	}
	return unpackBits(value, bits)
}
func packEta(value *polynomial) []byte {
	encoded := *value
	for i := range encoded {
		encoded[i] = 1 - encoded[i]
	}
	return packBits(&encoded, 2)
}
func unpackEta(value []byte) polynomial {
	out := unpackBits(value, 2)
	for i := range out {
		out[i] = 1 - out[i]
	}
	return out
}
func packDoubleEta(value *polynomial) []byte {
	encoded := *value
	for i := range encoded {
		encoded[i] = 2 - encoded[i]
	}
	return packBits(&encoded, 3)
}
func unpackDoubleEta(value []byte) polynomial {
	out := unpackBits(value, 3)
	for i := range out {
		out[i] = 2 - out[i]
	}
	return out
}

func packPublicKey(p params, seed []byte, publicVector polyVec) []byte {
	out := make([]byte, 0, p.publicKeyBytes)
	out = append(out, seed...)
	for i := range publicVector {
		out = append(out, packPolynomialQ(p, &publicVector[i])...)
	}
	return out
}
func unpackPublicKey(p params, publicKey []byte) polyMatrix {
	seed := publicKey[:seedBytes]
	offset := seedBytes
	packed := zeroVector(p.k)
	for i := range packed {
		packed[i] = unpackPolynomialQ(p, publicKey[offset:offset+p.polyQBytes])
		offset += p.polyQBytes
	}
	matrix := expandMatrix(p, seed, true)
	for row := range matrix {
		for column := 1; column < p.l; column++ {
			for i := range matrix[row][column] {
				matrix[row][column][i] *= 2
			}
		}
	}
	if p.mode == 5 {
		for row := range matrix {
			matrix[row][0] = packed[row]
		}
		return matrix
	}
	publicRandom := expandPublicVector(p, seed)
	firstColumn := transformVector(doubleVector(subtractVectors(publicRandom, doubleVector(packed))))
	for row := range matrix {
		matrix[row][0] = firstColumn[row]
	}
	return matrix
}
func packSecretKey(p params, publicKey []byte, first, second polyVec, key []byte) []byte {
	out := make([]byte, 0, p.secretKeyBytes)
	out = append(out, publicKey...)
	for i := range first {
		out = append(out, packEta(&first[i])...)
	}
	for i := range second {
		if p.mode == 5 {
			out = append(out, packEta(&second[i])...)
		} else {
			out = append(out, packDoubleEta(&second[i])...)
		}
	}
	out = append(out, key...)
	return out
}
func unpackSecretKey(p params, secretKey []byte) (polyMatrix, polyVec, polyVec, []byte) {
	publicKey := secretKey[:p.publicKeyBytes]
	offset := p.publicKeyBytes
	first := zeroVector(p.m)
	for i := range first {
		first[i] = unpackEta(secretKey[offset : offset+64])
		offset += 64
	}
	second := zeroVector(p.k)
	for i := range second {
		bytes := p.poly2EtaBytes
		if p.mode == 5 {
			second[i] = unpackEta(secretKey[offset : offset+bytes])
		} else {
			second[i] = unpackDoubleEta(secretKey[offset : offset+bytes])
		}
		offset += bytes
	}
	key := append([]byte(nil), secretKey[offset:offset+seedBytes]...)
	return unpackPublicKey(p, publicKey), first, second, key
}

func packHighBits(p params, value polyVec) []byte {
	out := make([]byte, 0, p.l*n*9/8)
	if p.mode != 5 {
		for i := range value {
			packed := make([]byte, n*9/8)
			for j := range value[i] {
				packed[j] = byte(value[i][j])
			}
			out = append(out, packed...)
		}
		return out
	}
	for i := range value {
		out = append(out, packBits(&value[i], 9)...)
	}
	return out
}
func packLeastSignificantBits(value *polynomial) []byte { return packBits(value, 1) }

type unpackedSignature struct {
	challenge               polynomial
	lowBits, highBits, hint polyVec
}

func packSignature(p params, challengeValue *polynomial, lowBits, highBits, hint polyVec) ([]byte, bool) {
	encodedHigh, ok := encodeHighBits(p, highBits)
	if !ok {
		return nil, false
	}
	encodedHint, ok := encodeHint(p, hint)
	if !ok {
		return nil, false
	}
	if len(encodedHigh) < p.baseEncodedHighZ1 || len(encodedHigh) > p.baseEncodedHighZ1+255 || len(encodedHint) < p.baseEncodedHint || len(encodedHint) > p.baseEncodedHint+255 {
		return nil, false
	}
	used := seedBytes + p.l*n + 2 + len(encodedHigh) + len(encodedHint)
	if used > p.signatureBytes {
		return nil, false
	}
	signature := make([]byte, p.signatureBytes)
	for i := 0; i < n; i++ {
		signature[i>>3] |= byte(challengeValue[i]) << uint(i&7)
	}
	offset := seedBytes
	for i := range lowBits {
		for j := range lowBits[i] {
			signature[offset+j] = byte(lowBits[i][j])
		}
		offset += n
	}
	signature[offset] = byte(len(encodedHigh) - p.baseEncodedHighZ1)
	offset++
	signature[offset] = byte(len(encodedHint) - p.baseEncodedHint)
	offset++
	copy(signature[offset:], encodedHigh)
	offset += len(encodedHigh)
	copy(signature[offset:], encodedHint)
	return signature, true
}
func unpackSignature(p params, signature []byte) (unpackedSignature, bool) {
	if len(signature) != p.signatureBytes {
		return unpackedSignature{}, false
	}
	var challengeValue polynomial
	for i := 0; i < n; i++ {
		challengeValue[i] = int32((signature[i>>3] >> uint(i&7)) & 1)
	}
	offset := seedBytes
	lowBits := zeroVector(p.l)
	for i := range lowBits {
		for j := range lowBits[i] {
			value := signature[offset+j]
			lowBits[i][j] = int32(int8(value))
		}
		offset += n
	}
	highLength := int(signature[offset]) + p.baseEncodedHighZ1
	offset++
	hintLength := int(signature[offset]) + p.baseEncodedHint
	offset++
	if offset+highLength+hintLength > len(signature) {
		return unpackedSignature{}, false
	}
	highBits, ok := decodeHighBits(p, signature[offset:offset+highLength])
	if !ok {
		return unpackedSignature{}, false
	}
	offset += highLength
	hint, ok := decodeHint(p, signature[offset:offset+hintLength])
	if !ok {
		return unpackedSignature{}, false
	}
	offset += hintLength
	for ; offset < len(signature); offset++ {
		if signature[offset] != 0 {
			return unpackedSignature{}, false
		}
	}
	return unpackedSignature{challengeValue, lowBits, highBits, hint}, true
}
