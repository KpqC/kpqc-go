package haetae

import "encoding/binary"

const ransByteL uint32 = 1 << 23
const scaleBits = 10
const scale uint32 = 1 << scaleBits

type symbolRange struct{ start, frequency uint32 }
type encodingParams struct {
	hint                []symbolRange
	hintCut, hintOffset int32
	high                []symbolRange
	highOffset          int32
}

func ranges(values ...uint32) []symbolRange {
	out := make([]symbolRange, len(values)/2)
	for i := range out {
		out[i] = symbolRange{values[2*i], values[2*i+1]}
	}
	return out
}

var encodings = map[int]encodingParams{
	2: {
		hint: ranges(
			0, 382, 382, 246, 628, 65, 693, 7,
			700, 1, 701, 1, 702, 1, 703, 1,
			704, 1, 705, 1, 706, 7, 713, 65, 778, 246,
		),
		hintCut:    6,
		hintOffset: 239,
		high: ranges(
			0, 1, 1, 1, 2, 1, 3, 5,
			8, 58, 66, 246, 312, 398, 710, 247,
			957, 59, 1016, 5, 1021, 1, 1022, 1, 1023, 1,
		),
		highOffset: 6,
	},
	3: {
		hint: ranges(
			0, 266, 266, 213, 479, 113, 592, 40,
			632, 9, 641, 1, 642, 1, 643, 1,
			644, 1, 645, 1, 646, 1, 647, 1,
			648, 1, 649, 9, 658, 40, 698, 113, 811, 213,
		),
		hintCut:    8,
		hintOffset: 235,
		high: ranges(
			0, 1, 1, 1, 2, 1, 3, 1,
			4, 8, 12, 37, 49, 112, 161, 216,
			377, 269, 646, 216, 862, 112, 974, 38,
			1012, 8, 1020, 1, 1021, 1, 1022, 1, 1023, 1,
		),
		highOffset: 8,
	},
	5: {
		hint: ranges(
			0, 122, 122, 117, 239, 102, 341, 81,
			422, 59, 481, 39, 520, 23, 543, 13,
			556, 6, 562, 3, 565, 1, 566, 1,
			567, 1, 568, 1, 569, 1, 570, 1,
			571, 1, 572, 1, 573, 1, 574, 1,
			575, 1, 576, 1, 577, 1, 578, 1,
			579, 3, 582, 6, 588, 13, 601, 24,
			625, 39, 664, 59, 723, 81, 804, 102, 906, 118,
		),
		hintCut:    16,
		hintOffset: 471,
		high: ranges(
			0, 1, 1, 1, 2, 1, 3, 1,
			4, 2, 6, 13, 19, 48, 67, 118,
			185, 204, 389, 245, 634, 204, 838, 118,
			956, 48, 1004, 14, 1018, 2, 1020, 1,
			1021, 1, 1022, 1, 1023, 1,
		),
		highOffset: 9,
	},
}

func flatten(value polyVec) []int32 {
	out := make([]int32, len(value)*n)
	for i := range value {
		copy(out[i*n:], value[i][:])
	}
	return out
}
func reshape(flat []int32, count int) polyVec {
	out := zeroVector(count)
	for i := range out {
		copy(out[i][:], flat[i*n:(i+1)*n])
	}
	return out
}

func encodeSymbols(symbols []int32, distribution []symbolRange) ([]byte, bool) {
	state := ransByteL
	emitted := make([]byte, 0)
	for i := len(symbols) - 1; i >= 0; i-- {
		symbol := int(symbols[i])
		if symbol < 0 || symbol >= len(distribution) {
			return nil, false
		}
		r := distribution[symbol]
		maximum := ((ransByteL >> scaleBits) << 8) * r.frequency
		for state >= maximum {
			emitted = append(emitted, byte(state))
			state >>= 8
		}
		state = (state/r.frequency)*scale + (state % r.frequency) + r.start
	}
	out := make([]byte, 4+len(emitted))
	binary.LittleEndian.PutUint32(out, state)
	for i := range emitted {
		out[4+i] = emitted[len(emitted)-1-i]
	}
	return out, true
}
func decodeSymbols(input []byte, count int, distribution []symbolRange) ([]int32, bool) {
	if len(input) < 4 {
		return nil, false
	}
	state := binary.LittleEndian.Uint32(input)
	if state < ransByteL || uint64(state) >= uint64(ransByteL)*256 {
		return nil, false
	}
	offset := 4
	out := make([]int32, count)
	for i := range out {
		cumulative := state & (scale - 1)
		symbol := -1
		for candidate, r := range distribution {
			if cumulative >= r.start && cumulative < r.start+r.frequency {
				symbol = candidate
				state = r.frequency*(state>>scaleBits) + cumulative - r.start
				break
			}
		}
		if symbol < 0 {
			return nil, false
		}
		out[i] = int32(symbol)
		for state < ransByteL && offset < len(input) {
			state = state<<8 | uint32(input[offset])
			offset++
		}
	}
	return out, state == ransByteL && offset == len(input)
}

func encodeHint(p params, hint polyVec) ([]byte, bool) {
	spec := encodings[p.mode]
	values := flatten(hint)
	for i, value := range values {
		if value > spec.hintCut && value <= spec.hintCut+spec.hintOffset {
			return nil, false
		}
		if value > spec.hintCut+spec.hintOffset {
			values[i] = value - spec.hintOffset
		}
	}
	return encodeSymbols(values, spec.hint)
}
func decodeHint(p params, input []byte) (polyVec, bool) {
	spec := encodings[p.mode]
	values, ok := decodeSymbols(input, p.k*n, spec.hint)
	if !ok {
		return nil, false
	}
	for i := range values {
		if values[i] > spec.hintCut {
			values[i] += spec.hintOffset
		}
	}
	return reshape(values, p.k), true
}
func encodeHighBits(p params, high polyVec) ([]byte, bool) {
	spec := encodings[p.mode]
	values := flatten(high)
	for i := range values {
		values[i] += spec.highOffset
	}
	return encodeSymbols(values, spec.high)
}
func decodeHighBits(p params, input []byte) (polyVec, bool) {
	spec := encodings[p.mode]
	values, ok := decodeSymbols(input, p.l*n, spec.high)
	if !ok {
		return nil, false
	}
	for i := range values {
		values[i] -= spec.highOffset
	}
	return reshape(values, p.l), true
}
