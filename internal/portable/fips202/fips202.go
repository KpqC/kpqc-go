// Package fips202 implements the SHA-3 and SHAKE primitives used by KpqC.
// Bytes are mapped to Keccak lanes explicitly, independently of host byte order.
package fips202

import "math/bits"

const (
	shake128Rate = 168
	shake256Rate = 136
	sha3256Rate  = 136
	sha3512Rate  = 72
)

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rotation = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var permutation = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func permute(state *[25]uint64) {
	for _, rc := range roundConstants {
		var columns [5]uint64
		for x := range columns {
			columns[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
		}
		for x := range columns {
			delta := columns[(x+4)%5] ^ bits.RotateLeft64(columns[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				state[x+5*y] ^= delta
			}
		}

		carried := state[1]
		for i, destination := range permutation {
			displaced := state[destination]
			state[destination] = bits.RotateLeft64(carried, rotation[i])
			carried = displaced
		}

		for y := 0; y < 5; y++ {
			offset := 5 * y
			copy(columns[:], state[offset:offset+5])
			for x := range columns {
				state[offset+x] = columns[x] ^ (^columns[(x+1)%5] & columns[(x+2)%5])
			}
		}
		state[0] ^= rc
	}
}

// Shake is an incremental SHAKE sponge.
type Shake struct {
	state     [25]uint64
	rate      int
	position  int
	squeezing bool
}

func NewShake128() *Shake { return &Shake{rate: shake128Rate} }
func NewShake256() *Shake { return &Shake{rate: shake256Rate} }

func (s *Shake) Absorb(input []byte) {
	if s.squeezing {
		panic("fips202: absorb after finalization")
	}
	for _, value := range input {
		if s.position == s.rate {
			permute(&s.state)
			s.position = 0
		}
		xorByte(&s.state, s.position, value)
		s.position++
	}
}

func (s *Shake) finalize() {
	if s.squeezing {
		return
	}
	if s.position == s.rate {
		permute(&s.state)
		s.position = 0
	}
	xorByte(&s.state, s.position, 0x1f)
	xorByte(&s.state, s.rate-1, 0x80)
	permute(&s.state)
	s.position = 0
	s.squeezing = true
}

func (s *Shake) Squeeze(output []byte) {
	s.finalize()
	for i := range output {
		if s.position == s.rate {
			permute(&s.state)
			s.position = 0
		}
		output[i] = readByte(&s.state, s.position)
		s.position++
	}
}

func xorByte(state *[25]uint64, position int, value byte) {
	state[position/8] ^= uint64(value) << (8 * (position % 8))
}

func readByte(state *[25]uint64, position int) byte {
	return byte(state[position/8] >> (8 * (position % 8)))
}

func Shake128(output, input []byte) {
	state := NewShake128()
	state.Absorb(input)
	state.Squeeze(output)
}

func Shake256(output, input []byte) {
	state := NewShake256()
	state.Absorb(input)
	state.Squeeze(output)
}

func SHA3256(input []byte) [32]byte {
	var output [32]byte
	sha3(output[:], input, sha3256Rate)
	return output
}

func SHA3512(input []byte) [64]byte {
	var output [64]byte
	sha3(output[:], input, sha3512Rate)
	return output
}

func sha3(output, input []byte, rate int) {
	var state [25]uint64
	position := 0
	for _, value := range input {
		if position == rate {
			permute(&state)
			position = 0
		}
		xorByte(&state, position, value)
		position++
	}
	if position == rate {
		permute(&state)
		position = 0
	}
	xorByte(&state, position, 0x06)
	xorByte(&state, rate-1, 0x80)
	permute(&state)
	for i := range output {
		if i != 0 && i%rate == 0 {
			permute(&state)
		}
		output[i] = readByte(&state, i%rate)
	}
}
