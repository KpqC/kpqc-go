// Package aimer implements AIMer v3 without cgo.
// All byte/field conversions are explicit little-endian conversions, so the
// implementation does not depend on the byte order of the host architecture.
package aimer

import (
	"encoding/binary"
	"math/bits"

	"kpqc.dev/internal/portable/ct"
	"kpqc.dev/internal/portable/entropy"
	"kpqc.dev/internal/portable/fips202"
)

type field [4]uint64

type params struct {
	bits, repetitions, parties, logParties int
	messagePrefix                          byte
	signatureBytes                         int
	exponents                              []int
}

func (p params) fieldBytes() int      { return p.bits / 8 }
func (p params) words() int           { return p.bits / 64 }
func (p params) inputSboxes() int     { return len(p.exponents) - 1 }
func (p params) commitmentBytes() int { return 2 * p.fieldBytes() }
func (p params) publicKeyBytes() int  { return 2 * p.fieldBytes() }
func (p params) secretKeyBytes() int  { return 3 * p.fieldBytes() }
func (p params) tapeBytes() int       { return (2*p.inputSboxes() + 3) * p.fieldBytes() }
func (p params) proofBytes() int {
	return p.logParties*p.fieldBytes() + p.commitmentBytes() + (2*p.inputSboxes()+3)*p.fieldBytes()
}

var (
	aimer128F = params{128, 33, 16, 4, 0x00, 6944, []int{3, 7, 11}}
	aimer128S = params{128, 17, 256, 8, 0x10, 4704, []int{3, 7, 11}}
	aimer192F = params{192, 49, 16, 4, 0x20, 15408, []int{11, 23, 47}}
	aimer192S = params{192, 25, 256, 8, 0x30, 10320, []int{11, 23, 47}}
	aimer256F = params{256, 65, 16, 4, 0x40, 31360, []int{3, 7, 11, 19}}
	aimer256S = params{256, 33, 256, 8, 0x50, 20224, []int{3, 7, 11, 19}}
)

type hash struct{ sponge *fips202.Shake }

func newHash(p params) *hash {
	if p.bits == 128 {
		return &hash{fips202.NewShake128()}
	}
	return &hash{fips202.NewShake256()}
}

func prefixedHash(p params, prefix byte) *hash {
	h := newHash(p)
	h.update([]byte{prefix})
	return h
}

func (h *hash) update(input []byte)   { h.sponge.Absorb(input) }
func (h *hash) squeeze(output []byte) { h.sponge.Squeeze(output) }

func fieldFromBytes(p params, input []byte) field {
	var output field
	for i := 0; i < p.words(); i++ {
		output[i] = binary.LittleEndian.Uint64(input[8*i:])
	}
	return output
}

func fieldToBytes(p params, value *field, output []byte) {
	for i := 0; i < p.words(); i++ {
		binary.LittleEndian.PutUint64(output[8*i:], value[i])
	}
}

func fieldBytes(p params, value *field) []byte {
	output := make([]byte, p.fieldBytes())
	fieldToBytes(p, value, output)
	return output
}

func fieldAdd(left, right *field) field {
	var output field
	for i := range output {
		output[i] = left[i] ^ right[i]
	}
	return output
}

func fieldAddAssign(target, value *field) {
	for i := range target {
		target[i] ^= value[i]
	}
}

func xorProductWord(product *[8]uint64, value *field, words, shift int) {
	wordShift, bitShift := shift/64, shift%64
	for i := 0; i < words; i++ {
		product[wordShift+i] ^= value[i] << bitShift
		if bitShift != 0 {
			product[wordShift+i+1] ^= value[i] >> (64 - bitShift)
		}
	}
}

func fieldMul(p params, left, right *field) field {
	words := p.words()
	var product [8]uint64
	for wordIndex := 0; wordIndex < words; wordIndex++ {
		remaining := right[wordIndex]
		for remaining != 0 {
			bit := bits.TrailingZeros64(remaining)
			xorProductWord(&product, left, words, wordIndex*64+bit)
			remaining &= remaining - 1
		}
	}
	return reduceProduct(p, &product)
}

func reduceProduct(p params, product *[8]uint64) field {
	reductions := [...]int{0, 1, 2, 7}
	if p.bits == 256 {
		reductions = [...]int{0, 2, 5, 10}
	}
	for bit := 2*p.bits - 1; bit >= p.bits; bit-- {
		if (product[bit/64]>>(bit%64))&1 == 0 {
			continue
		}
		product[bit/64] ^= uint64(1) << (bit % 64)
		base := bit - p.bits
		for _, term := range reductions {
			reduced := base + term
			product[reduced/64] ^= uint64(1) << (reduced % 64)
		}
	}
	var output field
	copy(output[:p.words()], product[:p.words()])
	return output
}

func fieldMulAdd(p params, target, left, right *field) {
	value := fieldMul(p, left, right)
	fieldAddAssign(target, &value)
}

var expandedByte = func() [256]uint16 {
	var table [256]uint16
	for value := range table {
		for bit := 0; bit < 8; bit++ {
			table[value] |= uint16((value>>bit)&1) << (2 * bit)
		}
	}
	return table
}()

func fieldSquare(p params, value *field) field {
	var product [8]uint64
	for word := 0; word < p.words(); word++ {
		for byteIndex := 0; byteIndex < 8; byteIndex++ {
			expanded := uint64(expandedByte[byte(value[word]>>(8*byteIndex))])
			position := 2 * (word*64 + byteIndex*8)
			product[position/64] ^= expanded << (position % 64)
		}
	}
	return reduceProduct(p, &product)
}

func fieldInverse(p params, value *field) field {
	power := *value
	var output field
	output[0] = 1
	for i := 1; i < p.bits; i++ {
		power = fieldSquare(p, &power)
		output = fieldMul(p, &output, &power)
	}
	return output
}

func matrixVector(matrix []field, vector *field, p params) field {
	var output field
	for bit := 0; bit < p.bits; bit++ {
		mask := uint64(0) - ((vector[bit/64] >> (bit % 64)) & 1)
		for word := 0; word < p.words(); word++ {
			output[word] ^= matrix[bit][word] & mask
		}
	}
	return output
}

type linear struct {
	matrices [][]field
	vectors  []field
}

func squeezeInvertibleMatrix(p params, h *hash) []field {
	lower := make([]field, p.bits)
	upper := make([]field, p.bits)
	bytes := make([]byte, p.fieldBytes())
	for row := 0; row < p.bits; row++ {
		h.squeeze(bytes)
		random := fieldFromBytes(p, bytes)
		bit := row % 64
		diagonal := uint64(1) << bit
		lowerMask := ^uint64(0) << bit
		upperMask := ^lowerMask
		crossing := row / 64
		copy(upper[row][:crossing], random[:crossing])
		lower[row][crossing] = random[crossing]&lowerMask | diagonal
		upper[row][crossing] = random[crossing]&upperMask | diagonal
		copy(lower[row][crossing+1:p.words()], random[crossing+1:p.words()])
	}
	output := make([]field, p.bits)
	for row := range output {
		output[row] = matrixVector(lower, &upper[row], p)
	}
	return output
}

func generateLinear(p params, iv []byte) linear {
	h := newHash(p)
	h.update(iv)
	matrices := make([][]field, 2*p.inputSboxes())
	for i := range matrices {
		matrices[i] = squeezeInvertibleMatrix(p, h)
	}
	vectors := make([]field, p.inputSboxes()+1)
	bytes := make([]byte, p.fieldBytes())
	for i := range vectors {
		h.squeeze(bytes)
		vectors[i] = fieldFromBytes(p, bytes)
	}
	return linear{matrices, vectors}
}

func aimEncrypt(p params, plaintextBytes, iv []byte) ([]byte, bool) {
	linear := generateLinear(p, iv)
	plaintext := fieldFromBytes(p, plaintextBytes)
	states := make([]field, p.inputSboxes())
	for index := range states {
		state := matrixVector(linear.matrices[index], &plaintext, p)
		fieldAddAssign(&state, &linear.vectors[index])
		if fieldZero(p, &state) {
			return nil, false
		}
		inverse := fieldInverse(p, &state)
		for i := 0; i < p.exponents[index]; i++ {
			state = fieldSquare(p, &state)
		}
		state[0] ^= 1
		state = fieldMul(p, &state, &inverse)
		states[index] = matrixVector(linear.matrices[index+p.inputSboxes()], &state, p)
	}
	state := states[0]
	for i := 1; i < len(states); i++ {
		fieldAddAssign(&state, &states[i])
	}
	fieldAddAssign(&state, &linear.vectors[p.inputSboxes()])
	if fieldZero(p, &state) {
		return nil, false
	}
	inverse := fieldInverse(p, &state)
	for i := 0; i < p.exponents[p.inputSboxes()]; i++ {
		state = fieldSquare(p, &state)
	}
	state[0] ^= 1
	state = fieldMul(p, &state, &inverse)
	fieldAddAssign(&state, &plaintext)
	return fieldBytes(p, &state), true
}

func fieldZero(p params, value *field) bool {
	var combined uint64
	for i := 0; i < p.words(); i++ {
		combined |= value[i]
	}
	return combined == 0
}

func sboxOutputs(p params, linear *linear, plaintext, ciphertext *field) []field {
	output := make([]field, p.inputSboxes()+1)
	for index := 0; index < p.inputSboxes(); index++ {
		value := matrixVector(linear.matrices[index], plaintext, p)
		fieldAddAssign(&value, &linear.vectors[index])
		inverse := fieldInverse(p, &value)
		for i := 0; i < p.exponents[index]; i++ {
			value = fieldSquare(p, &value)
		}
		value[0] ^= 1
		output[index] = fieldMul(p, &value, &inverse)
	}
	output[p.inputSboxes()] = fieldAdd(plaintext, ciphertext)
	return output
}

type tape struct {
	plaintext field
	y, a      []field
	c         field
}

func zeroTape(p params) tape {
	return tape{y: make([]field, p.inputSboxes()), a: make([]field, p.inputSboxes()+1)}
}

func tapeFromBytes(p params, bytes []byte) tape {
	size, offset := p.fieldBytes(), 0
	next := func() field {
		value := fieldFromBytes(p, bytes[offset:offset+size])
		offset += size
		return value
	}
	result := zeroTape(p)
	result.plaintext = next()
	for i := range result.y {
		result.y[i] = next()
	}
	for i := range result.a {
		result.a[i] = next()
	}
	result.c = next()
	return result
}

type multiplicationCheck struct {
	x, z, a, b []field
	c          field
}

func aimMPC(p params, linear *linear, tape *tape, ciphertext *field, party int) multiplicationCheck {
	last := party == p.parties-1
	x := make([]field, p.inputSboxes()+1)
	z := make([]field, p.inputSboxes()+1)
	b := append([]field(nil), tape.y...)
	b = append(b, tape.plaintext)
	if last {
		fieldAddAssign(&b[p.inputSboxes()], ciphertext)
	}
	for index := 0; index < p.inputSboxes(); index++ {
		x[index] = matrixVector(linear.matrices[index], &tape.plaintext, p)
		if last {
			fieldAddAssign(&x[index], &linear.vectors[index])
		}
	}
	for index := range tape.y {
		contribution := matrixVector(linear.matrices[index+p.inputSboxes()], &tape.y[index], p)
		fieldAddAssign(&x[p.inputSboxes()], &contribution)
	}
	if last {
		fieldAddAssign(&x[p.inputSboxes()], &linear.vectors[p.inputSboxes()])
	}
	for index := 0; index <= p.inputSboxes(); index++ {
		z[index] = fieldSquare(p, &x[index])
		for i := 1; i < p.exponents[index]; i++ {
			z[index] = fieldSquare(p, &z[index])
		}
		if last {
			z[index][0] ^= 1
		}
	}
	return multiplicationCheck{x, z, append([]field(nil), tape.a...), b, tape.c}
}

func commitAndExpandTape(p params, salt []byte, repetition, party int, seed []byte) ([]byte, tape) {
	h := prefixedHash(p, 5)
	h.update(salt)
	h.update([]byte{byte(repetition), byte(party)})
	h.update(seed)
	commitment := make([]byte, p.commitmentBytes())
	h.squeeze(commitment)
	bytes := make([]byte, p.tapeBytes())
	h.squeeze(bytes)
	return commitment, tapeFromBytes(p, bytes)
}

func expandTree(p params, salt []byte, repetition int, root []byte) [][]byte {
	nodes := make([][]byte, 2*p.parties-1)
	for i := range nodes {
		nodes[i] = make([]byte, p.fieldBytes())
	}
	copy(nodes[0], root)
	for node := 1; node < p.parties; node++ {
		h := prefixedHash(p, 4)
		h.update(salt)
		h.update([]byte{byte(repetition), byte(node)})
		h.update(nodes[node-1])
		children := make([]byte, 2*p.fieldBytes())
		h.squeeze(children)
		copy(nodes[2*node-1], children[:p.fieldBytes()])
		copy(nodes[2*node], children[p.fieldBytes():])
	}
	return nodes
}

func revealPath(p params, nodes [][]byte, covered int) []byte {
	output := make([]byte, 0, p.logParties*p.fieldBytes())
	index := covered + p.parties
	for i := 0; i < p.logParties; i++ {
		output = append(output, nodes[(index^1)-1]...)
		index >>= 1
	}
	return output
}

func reconstructTree(p params, salt, path []byte, repetition, covered int) [][]byte {
	size := p.fieldBytes()
	nodes := make([][]byte, 2*p.parties-2)
	for i := range nodes {
		nodes[i] = make([]byte, size)
	}
	for depth := 1; depth < p.logParties; depth++ {
		sibling := ((covered + p.parties) >> (p.logParties - depth)) ^ 1
		copy(nodes[sibling-2], path[(p.logParties-depth)*size:][:size])
		for index := 1 << depth; index < 2<<depth; index++ {
			h := prefixedHash(p, 4)
			h.update(salt)
			h.update([]byte{byte(repetition), byte(index)})
			h.update(nodes[index-2])
			children := make([]byte, 2*size)
			h.squeeze(children)
			copy(nodes[2*index-2], children[:size])
			copy(nodes[2*index-1], children[size:])
		}
	}
	sibling := (covered + p.parties) ^ 1
	copy(nodes[sibling-2], path[:size])
	return nodes
}

type signatureLayout struct{ p params }

func (l signatureLayout) salt(signature []byte) []byte { return signature[:l.p.fieldBytes()] }
func (l signatureLayout) h1(signature []byte) []byte {
	start := l.p.fieldBytes()
	return signature[start : start+l.p.commitmentBytes()]
}
func (l signatureLayout) h2(signature []byte) []byte {
	start := l.p.fieldBytes() + l.p.commitmentBytes()
	return signature[start : start+l.p.commitmentBytes()]
}
func (l signatureLayout) proofStart(repetition int) int {
	return l.p.fieldBytes() + 2*l.p.commitmentBytes() + repetition*l.p.proofBytes()
}
func (l signatureLayout) proof(signature []byte, repetition, relative, length int) []byte {
	start := l.proofStart(repetition) + relative
	return signature[start : start+length]
}
func (l signatureLayout) revealOffset() int            { return 0 }
func (l signatureLayout) missingCommitmentOffset() int { return l.p.logParties * l.p.fieldBytes() }
func (l signatureLayout) deltaOffset() int {
	return l.missingCommitmentOffset() + l.p.commitmentBytes()
}
func (l signatureLayout) missingAlphaOffset() int {
	return l.deltaOffset() + (l.p.inputSboxes()+2)*l.p.fieldBytes()
}

func updateFields(h *hash, p params, fields []field) {
	for i := range fields {
		h.update(fieldBytes(p, &fields[i]))
	}
}

func messageDigest(p params, publicKey, prefix, message []byte) []byte {
	h := prefixedHash(p, p.messagePrefix)
	h.update(publicKey)
	h.update(prefix)
	h.update(message)
	digest := make([]byte, p.commitmentBytes())
	h.squeeze(digest)
	return digest
}

func challengedIndices(p params, h2 []byte) []int {
	h := newHash(p)
	h.update(h2)
	bytes := make([]byte, p.repetitions)
	h.squeeze(bytes)
	indices := make([]int, p.repetitions)
	for i, value := range bytes {
		indices[i] = int(value) & (p.parties - 1)
	}
	return indices
}

func generateKeyPair(p params, publicKey, secretKey []byte) int {
	if len(publicKey) != p.publicKeyBytes() || len(secretKey) != p.secretKeyBytes() {
		return -1
	}
	size := p.fieldBytes()
	for {
		plaintext, iv := make([]byte, size), make([]byte, size)
		if !entropy.Fill(plaintext) || !entropy.Fill(iv) {
			return -1
		}
		ciphertext, ok := aimEncrypt(p, plaintext, iv)
		if !ok {
			continue
		}
		copy(publicKey[:size], iv)
		copy(publicKey[size:], ciphertext)
		copy(secretKey[:size], plaintext)
		copy(secretKey[size:], publicKey)
		return 0
	}
}

func sign(p params, signature []byte, length *uint64, message, context, secretKey []byte) int {
	if len(context) > 255 || len(signature) != p.signatureBytes || len(secretKey) != p.secretKeyBytes() {
		return -1
	}
	size, commitSize := p.fieldBytes(), p.commitmentBytes()
	layout := signatureLayout{p}
	clear(signature)
	randomness := make([]byte, size)
	if !entropy.Fill(randomness) {
		return -1
	}
	prefix := append([]byte{byte(len(context))}, context...)
	publicKey := secretKey[size:]
	digest := messageDigest(p, publicKey, prefix, message)
	plaintext := fieldFromBytes(p, secretKey[:size])
	ciphertext := fieldFromBytes(p, secretKey[2*size:3*size])
	linear := generateLinear(p, secretKey[size:2*size])
	outputs := sboxOutputs(p, &linear, &plaintext, &ciphertext)

	seedHash := prefixedHash(p, 3)
	seedHash.update(secretKey[:size])
	seedHash.update(digest)
	seedHash.update(randomness)
	seedHash.squeeze(layout.salt(signature))
	salt := append([]byte(nil), layout.salt(signature)...)
	roots := make([]byte, p.repetitions*size)
	seedHash.squeeze(roots)

	h1Hash := prefixedHash(p, 1)
	h1Hash.update(digest)
	h1Hash.update(salt)
	allNodes := make([][][]byte, p.repetitions)
	allCommits := make([][][]byte, p.repetitions)
	checks := make([][]multiplicationCheck, p.repetitions)

	for repetition := 0; repetition < p.repetitions; repetition++ {
		nodes := expandTree(p, salt, repetition, roots[repetition*size:(repetition+1)*size])
		commitments := make([][]byte, 0, p.parties)
		repetitionChecks := make([]multiplicationCheck, 0, p.parties)
		delta := zeroTape(p)
		deltaBytes := make([]byte, (p.inputSboxes()+2)*size)
		for party := 0; party < p.parties; party++ {
			commitment, tape := commitAndExpandTape(p, salt, repetition, party, nodes[party+p.parties-1])
			commitments = append(commitments, commitment)
			fieldAddAssign(&delta.plaintext, &tape.plaintext)
			for i := range delta.y {
				fieldAddAssign(&delta.y[i], &tape.y[i])
			}
			for i := range delta.a {
				fieldAddAssign(&delta.a[i], &tape.a[i])
			}
			fieldAddAssign(&delta.c, &tape.c)
			if party == p.parties-1 {
				fieldAddAssign(&delta.plaintext, &plaintext)
				fieldToBytes(p, &delta.plaintext, deltaBytes[:size])
				fieldAddAssign(&tape.plaintext, &delta.plaintext)
				for index := 0; index < p.inputSboxes(); index++ {
					fieldAddAssign(&delta.y[index], &outputs[index])
					fieldToBytes(p, &delta.y[index], deltaBytes[(index+1)*size:(index+2)*size])
					fieldAddAssign(&tape.y[index], &delta.y[index])
				}
				for i := range delta.a {
					fieldMulAdd(p, &delta.c, &delta.a[i], &outputs[i])
				}
				fieldToBytes(p, &delta.c, deltaBytes[(p.inputSboxes()+1)*size:])
				fieldAddAssign(&tape.c, &delta.c)
			}
			repetitionChecks = append(repetitionChecks, aimMPC(p, &linear, &tape, &ciphertext, party))
		}
		for _, commitment := range commitments {
			h1Hash.update(commitment)
		}
		h1Hash.update(deltaBytes)
		copy(layout.proof(signature, repetition, layout.deltaOffset(), len(deltaBytes)), deltaBytes)
		allNodes[repetition], allCommits[repetition], checks[repetition] = nodes, commitments, repetitionChecks
	}
	h1Hash.squeeze(layout.h1(signature))
	h1 := append([]byte(nil), layout.h1(signature)...)

	epsilonHash := newHash(p)
	epsilonHash.update(h1)
	h2Hash := prefixedHash(p, 2)
	h2Hash.update(h1)
	h2Hash.update(salt)
	alphaShares := make([][][]field, p.repetitions)
	for repetition := 0; repetition < p.repetitions; repetition++ {
		epsilonBytes := make([]byte, (p.inputSboxes()+1)*size)
		epsilonHash.squeeze(epsilonBytes)
		epsilons := make([]field, p.inputSboxes()+1)
		for i := range epsilons {
			epsilons[i] = fieldFromBytes(p, epsilonBytes[i*size:(i+1)*size])
		}
		alpha := make([]field, p.inputSboxes()+1)
		vShares := make([]field, p.parties)
		alphaShares[repetition] = make([][]field, p.parties)
		for party := 0; party < p.parties; party++ {
			alphaShares[repetition][party] = make([]field, p.inputSboxes()+1)
			vShares[party] = checks[repetition][party].c
			for index := 0; index <= p.inputSboxes(); index++ {
				value := checks[repetition][party].a[index]
				fieldMulAdd(p, &value, &checks[repetition][party].x[index], &epsilons[index])
				alphaShares[repetition][party][index] = value
				fieldAddAssign(&alpha[index], &value)
				fieldMulAdd(p, &vShares[party], &checks[repetition][party].z[index], &epsilons[index])
			}
		}
		for party := 0; party < p.parties; party++ {
			for index := range alpha {
				fieldMulAdd(p, &vShares[party], &checks[repetition][party].b[index], &alpha[index])
			}
		}
		for party := range alphaShares[repetition] {
			updateFields(h2Hash, p, alphaShares[repetition][party])
		}
		updateFields(h2Hash, p, vShares)
	}
	h2Hash.squeeze(layout.h2(signature))
	indices := challengedIndices(p, layout.h2(signature))
	for repetition, covered := range indices {
		path := revealPath(p, allNodes[repetition], covered)
		copy(layout.proof(signature, repetition, layout.revealOffset(), len(path)), path)
		copy(layout.proof(signature, repetition, layout.missingCommitmentOffset(), commitSize), allCommits[repetition][covered])
		missing := make([]byte, (p.inputSboxes()+1)*size)
		for i := range alphaShares[repetition][covered] {
			fieldToBytes(p, &alphaShares[repetition][covered][i], missing[i*size:(i+1)*size])
		}
		copy(layout.proof(signature, repetition, layout.missingAlphaOffset(), len(missing)), missing)
	}
	*length = uint64(p.signatureBytes)
	return 0
}

func verify(p params, signature, message, context, publicKey []byte) int {
	if len(context) > 255 || len(signature) != p.signatureBytes || len(publicKey) != p.publicKeyBytes() {
		return 1
	}
	size, commitSize := p.fieldBytes(), p.commitmentBytes()
	layout := signatureLayout{p}
	salt, h1, h2 := layout.salt(signature), layout.h1(signature), layout.h2(signature)
	linear := generateLinear(p, publicKey[:size])
	ciphertext := fieldFromBytes(p, publicKey[size:])
	indices := challengedIndices(p, h2)
	epsilonHash := newHash(p)
	epsilonHash.update(h1)
	prefix := append([]byte{byte(len(context))}, context...)
	digest := messageDigest(p, publicKey, prefix, message)
	h1Hash := prefixedHash(p, 1)
	h1Hash.update(digest)
	h1Hash.update(salt)
	h2Hash := prefixedHash(p, 2)
	h2Hash.update(h1)
	h2Hash.update(salt)

	for repetition, covered := range indices {
		path := layout.proof(signature, repetition, layout.revealOffset(), p.logParties*size)
		nodes := reconstructTree(p, salt, path, repetition, covered)
		epsilonBytes := make([]byte, (p.inputSboxes()+1)*size)
		epsilonHash.squeeze(epsilonBytes)
		epsilons := make([]field, p.inputSboxes()+1)
		for i := range epsilons {
			epsilons[i] = fieldFromBytes(p, epsilonBytes[i*size:(i+1)*size])
		}
		alpha := make([]field, p.inputSboxes()+1)
		alphaShares := make([][]field, p.parties)
		bShares := make([][]field, p.parties)
		vShares := make([]field, p.parties)
		for party := 0; party < p.parties; party++ {
			alphaShares[party] = make([]field, p.inputSboxes()+1)
			bShares[party] = make([]field, p.inputSboxes()+1)
			if party == covered {
				h1Hash.update(layout.proof(signature, repetition, layout.missingCommitmentOffset(), commitSize))
				missing := layout.proof(signature, repetition, layout.missingAlphaOffset(), (p.inputSboxes()+1)*size)
				for index := range alphaShares[party] {
					alphaShares[party][index] = fieldFromBytes(p, missing[index*size:(index+1)*size])
					fieldAddAssign(&alpha[index], &alphaShares[party][index])
				}
				continue
			}
			commitment, tape := commitAndExpandTape(p, salt, repetition, party, nodes[p.parties+party-2])
			h1Hash.update(commitment)
			if party == p.parties-1 {
				delta := layout.proof(signature, repetition, layout.deltaOffset(), (p.inputSboxes()+2)*size)
				offset := 0
				next := func() field {
					value := fieldFromBytes(p, delta[offset:offset+size])
					offset += size
					return value
				}
				value := next()
				fieldAddAssign(&tape.plaintext, &value)
				for i := range tape.y {
					value = next()
					fieldAddAssign(&tape.y[i], &value)
				}
				value = next()
				fieldAddAssign(&tape.c, &value)
			}
			check := aimMPC(p, &linear, &tape, &ciphertext, party)
			vShares[party] = check.c
			for index := 0; index <= p.inputSboxes(); index++ {
				alphaShares[party][index] = check.a[index]
				fieldMulAdd(p, &alphaShares[party][index], &check.x[index], &epsilons[index])
				fieldAddAssign(&alpha[index], &alphaShares[party][index])
				bShares[party][index] = check.b[index]
				fieldMulAdd(p, &vShares[party], &check.z[index], &epsilons[index])
			}
		}
		for party := 0; party < p.parties; party++ {
			if party == covered {
				continue
			}
			for index := range alpha {
				fieldMulAdd(p, &vShares[party], &bShares[party][index], &alpha[index])
			}
			value := vShares[party]
			fieldAddAssign(&vShares[covered], &value)
		}
		for party := range alphaShares {
			updateFields(h2Hash, p, alphaShares[party])
		}
		updateFields(h2Hash, p, vShares)
		h1Hash.update(layout.proof(signature, repetition, layout.deltaOffset(), (p.inputSboxes()+2)*size))
	}
	computedH1, computedH2 := make([]byte, commitSize), make([]byte, commitSize)
	h1Hash.squeeze(computedH1)
	h2Hash.squeeze(computedH2)
	if ct.Equal(computedH1, h1) == 1 && ct.Equal(computedH2, h2) == 1 {
		return 0
	}
	return 1
}

func KeyPair128F(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer128F, publicKey, secretKey)
}
func Sign128F(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer128F, signature, length, message, context, secretKey)
}
func Verify128F(signature, message, context, publicKey []byte) int {
	return verify(aimer128F, signature, message, context, publicKey)
}

func KeyPair128S(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer128S, publicKey, secretKey)
}
func Sign128S(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer128S, signature, length, message, context, secretKey)
}
func Verify128S(signature, message, context, publicKey []byte) int {
	return verify(aimer128S, signature, message, context, publicKey)
}

func KeyPair192F(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer192F, publicKey, secretKey)
}
func Sign192F(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer192F, signature, length, message, context, secretKey)
}
func Verify192F(signature, message, context, publicKey []byte) int {
	return verify(aimer192F, signature, message, context, publicKey)
}

func KeyPair192S(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer192S, publicKey, secretKey)
}
func Sign192S(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer192S, signature, length, message, context, secretKey)
}
func Verify192S(signature, message, context, publicKey []byte) int {
	return verify(aimer192S, signature, message, context, publicKey)
}

func KeyPair256F(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer256F, publicKey, secretKey)
}
func Sign256F(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer256F, signature, length, message, context, secretKey)
}
func Verify256F(signature, message, context, publicKey []byte) int {
	return verify(aimer256F, signature, message, context, publicKey)
}

func KeyPair256S(publicKey, secretKey []byte) int {
	return generateKeyPair(aimer256S, publicKey, secretKey)
}
func Sign256S(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return sign(aimer256S, signature, length, message, context, secretKey)
}
func Verify256S(signature, message, context, publicKey []byte) int {
	return verify(aimer256S, signature, message, context, publicKey)
}
