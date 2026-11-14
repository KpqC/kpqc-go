package haetae

import (
	"encoding/binary"
	"math/bits"
	"strconv"
	"strings"
)

const u48 uint64 = (1 << 48) - 1

type fixed96 struct{ low, high uint64 }
type hyperConstants struct {
	startCube, startTimesThreeHalves fixed96
	scalar                           uint64
}

var hyperSpecs = map[int]hyperConstants{
	2: {fixed96{0x770077e2e41a, 0x1162}, fixed96{0x693861ad937b, 0x9caa56}, 2643021496320},
	3: {fixed96{0x1a2935cfae68, 0x978}, fixed96{0x7ad215218533, 0x7ff1c9}, 4916390789120},
	5: {fixed96{0x700ff3e8890d, 0x702}, fixed96{0x5768588eed31, 0x73bd40}, 5997831421952},
}

func normalizeFixed(v fixed96) fixed96 { return fixed96{v.low & u48, v.high + (v.low >> 48)} }
func multiply48(left, right uint64) (uint64, uint64) {
	high, low := bits.Mul64(left, right)
	return low & u48, (high << 16) ^ (low >> 48)
}
func conditionalNegate(v fixed96, sign uint64) fixed96 {
	mask := uint64(0) - sign
	return normalizeFixed(fixed96{(v.low ^ (mask & u48)) + sign, v.high ^ mask})
}
func addFixed(left, right fixed96) fixed96 {
	return fixed96{left.low + right.low, left.high + right.high}
}
func multiplyFixed(left, right fixed96) fixed96 {
	low, high := multiply48(left.low, right.low)
	low = high + (((low >> 47) + 1) >> 1)
	crossLow, crossHigh := multiply48(left.low, right.high)
	low += crossLow
	high = crossHigh
	c2Low, c2High := multiply48(left.high, right.low)
	low += c2Low
	high += c2High
	low += 1 << 27
	low >>= 28
	low += (high << 20) & u48
	high >>= 28
	upperHigh, upperLow := bits.Mul64(left.high, right.high)
	low += (upperLow << 20) & u48
	high += (upperLow >> 28) + (upperHigh << 36)
	return normalizeFixed(fixed96{low, high})
}
func squareFixed(v fixed96) fixed96 {
	low, high := multiply48(v.low, v.low)
	low = (low >> 48) + high
	crossLow, crossHigh := multiply48(v.low, v.high)
	low += crossLow << 1
	high = crossHigh << 1
	low >>= 28
	low += (high << 20) & u48
	high >>= 28
	upperHigh, upperLow := bits.Mul64(v.high, v.high)
	low += (upperLow << 20) & u48
	high += (upperLow >> 28) + (upperHigh << 36)
	return normalizeFixed(fixed96{low, high})
}
func subtractFixed(left, right fixed96) fixed96 { return addFixed(left, conditionalNegate(right, 1)) }
func subtractThreeHalves(v fixed96) fixed96 {
	out := conditionalNegate(v, 1)
	out.high += 3 << 27
	return normalizeFixed(out)
}
func multiplyUnsignedSigned(value, signed fixed96) fixed96 {
	sign := signed.high >> 63
	absolute := conditionalNegate(signed, sign)
	return conditionalNegate(multiplyFixed(absolute, value), sign)
}
func inverseSquareRoot(mode int, half fixed96) fixed96 {
	spec := hyperSpecs[mode]
	result := subtractFixed(spec.startTimesThreeHalves, multiplyFixed(half, spec.startCube))
	for i := 0; i < 6; i++ {
		factor := subtractThreeHalves(multiplyFixed(half, squareFixed(result)))
		result = multiplyUnsignedSigned(result, factor)
	}
	return result
}
func multiplyFixedHigh(value fixed96, scalar uint64) fixed96 {
	low, high := multiply48(value.low, scalar)
	upperLow, upperHigh := multiply48(value.high, scalar)
	high += upperLow
	low += 1 << 27
	low >>= 28
	low += (high << 20) & u48
	high >>= 28
	high += upperHigh << 20
	return normalizeFixed(fixed96{low, high})
}
func multiplyRound13(value uint64, factor fixed96, sign byte) int32 {
	fixed := fixed96{(value & 0xffffffff) << 16, value >> 32}
	product := multiplyFixed(fixed, factor)
	rounded := int32((product.high + (1 << 14)) >> 15)
	if sign != 0 {
		return -rounded
	}
	return rounded
}

func signedMultiplyHigh48(left int64, right uint64) int64 {
	// Compute ceil(left*right/2^48) using a fixed-width 128-bit product.
	// For a negative dividend, ceil(-x/d) is -floor(x/d).
	sign := uint64(left >> 63)
	magnitude := (uint64(left) ^ sign) - sign
	high, low := bits.Mul64(magnitude, right)
	quotient := high<<16 | low>>48
	remainder := low & u48
	nonzeroRemainder := (remainder | (0 - remainder)) >> 63
	quotient += nonzeroRemainder & (^sign & 1)
	return int64((quotient ^ sign) - sign)
}
func approximateExponential(value uint64) uint64 {
	result := int64(55868746)
	result = signedMultiplyHigh48(result, value) - 743564434
	result = signedMultiplyHigh48(result, value) + 6953427278
	result = signedMultiplyHigh48(result, value) - 55833338892
	result = signedMultiplyHigh48(result, value) + 390932311155
	result = signedMultiplyHigh48(result, value) - 2345623661771
	result = signedMultiplyHigh48(result, value) + 11728123872951
	result = signedMultiplyHigh48(result, value) - 46912496106200
	result = signedMultiplyHigh48(result, value) + 140737488354861
	result = signedMultiplyHigh48(result, value) - 281474976710650
	result = signedMultiplyHigh48(result, value) + 281474976710657
	return uint64(result)
}

const cdtHighText = `
	063a5 0c718 129f6 18bdf 1ec73 24b59 2a83a 302c6
	35ab6 3afc7 401be 4506a 49ba1 4e343 52736 5676c
	5a3dc 5dc86 61172 642ad 6704c 69a68 6c120 6e496
	704ef 72255 73cf1 754f0 76a7c 77dc4 78ef2 79e32
	7abaf 7b78f 7c1fb 7cb17 7d304 7d9e4 7dfd4 7e4f0
	7e950 7ed0d 7f03b 7f2ec 7f531 7f71a 7f8b3 7fa08
	7fb24 7fc0e 7fccf 7fd6e 7fdf0 7fe5a 7feaf 7fef5
	7ff2c 7ff59 7ff7d 7ff99 7ffb0 7ffc2 7ffd0 7ffdb
	7ffe3 7ffea 7ffef 7fff3 7fff6 7fff8 7fffa 7fffb
	7fffd 7fffd 7fffe 7fffe
`
const cdtLowText = `
	0aa572bc88db1e28 4f3820e69064b2ee d68dc44dd1418704 6587a04d9b97b1dd 9b843ce0a65d0050 02b62cb869003e7d
	0d44f194f8bf43c6 faa0c7acb211b4db a11387f7f524be80 18526ca6f2ceb77f 42a01a906b7dad17 32e5337a1966b9a7
	6f00f7ac9735f58a 0e6c48f40642ba60 b6192fa1afb5e4ec 7339dba8ffc2fcf5 7746cbe1ac90c9eb b83004341d78466f
	781dcca572bb3d8a b880376cc82a5384 9c68a5c477dfecb9 be45ceb02a25fef3 7d1a8ccd208dbaa1 452c002b9085e7db
	d7ef361c5551378d 96b4ff49d9e5a8bb d337c94ede732d83 28c75b8d3fe83c38 e05d7bd130fe20e0 6170e60b76d85108
	b0e59892414901ff ff05cf70b911f3de 4501460fdfd508c9 f20b1303a2a54906 a7d3badbeb04b20c 05ce666b741b666d
	826e689fded20430 5155d1354fcf6ff6 55469226a1d318f6 1c8d3820cfa9cabc e68d83bbf700fc40 b1152d8944042803
	4c1e741aabe53700 72b94c56e0f9a967 e7e5a80a79e4539c 9641c5d11feb4d12 b18b71598b73dde0 d9112fb5a7904d7e
	3a4f57cbefabc820 b314025fd5022976 f2a2b228aab1981b 996ce1e60378cd98 570ec64b38e3ca90 0657269615dcd7c6
	c7360038bdc85312 167fa02a57a8ae1a e380fab2ea9b2bef a36e6abd6509b5a2 62bfcf1d6ba81c37 d4946e8bf96caa93
	603e6262ea8cda2d 2d18c8b333ae9203 2ccdedb5a7718d61 24333ecab8497c0a b2e06eb33bf2b7d9 59a5f6c550dfe7e2
	800548f3927f906e 78cac146b573bc40 85e6dadec4b6aff1 dba17dfa17def8ec a33f84d06ce20a93 fd2fe967c5186746
	02d37ecd7e9b180f c7efafa8bd33f0bb 5bda826341e791cc ca6c1c6ce045599f 1cc02c0faa9a526e 59d002901a4a4e52
	86ecbd139ce07540 a81f9f15ffb47f4c c075b17481687af0 d23ad13e68301c65 df27955fae1c84cb e884cdb07368c266
	ef46d4f897fc83f6 f4227e46663ec049 f79d091c1b5aff07 fa183c533c3890a6 fbdb8a602066b0f2 fd1af06df3db86b7
	fdfc1a818587e2aa fe9a37a348ac2a93 ff08d0797970dbfe ff55df73fd7a00bc ff8b5aa573bca5ce ffb053c109f51681
	ffc9c9bd39a036ec ffdb40bd4ee1f846 ffe72fa859b20a4a ffef4edda93d266d fff4d07a9fb0d4e0 fff88868ef31b1cc
	fffb08c16a3f5f0c fffcb5d30be5cabf fffdd43465d95fe6 fffe929a538ad2fa ffff10b1c2119732 ffff63df8795a2c9
	ffff9a87a0a9f2af ffffbe4df6f0f4a9 ffffd5a10f204910 ffffe4c6f1668b32 ffffee939680bfaf fffff4e4216290db
	fffff8f1c044613e fffffb892dc2b174 fffffd2fb4188608 fffffe3bc0a56eba fffffee523b218c6 ffffff4fc31097e3
	ffffff929d76dbeb ffffffbc5e7c0350 ffffffd6586c6684 ffffffe6716865f7 fffffff0613c76e2 fffffff67d62ab64
	fffffffa3b6664c0 fffffffc83e13d66 fffffffde713ef71 fffffffebe18936f ffffffff3fbfc997 ffffffff8d9fa29a
	ffffffffbc372590 ffffffffd7fb7dfd ffffffffe87747f9 fffffffff2368b89 fffffffff7f44d88 fffffffffb52a49b
	fffffffffd4a9ffb fffffffffe700579 ffffffffff1a287f ffffffffff7c6f06 ffffffffffb4fa99 ffffffffffd56300
	ffffffffffe7e364 fffffffffff268d7 fffffffffff85e8e fffffffffffbbb6f fffffffffffd9f49 fffffffffffeae2c
	ffffffffffff453d ffffffffffff9928 ffffffffffffc797 ffffffffffffe12f ffffffffffffef3c fffffffffffff6eb
	fffffffffffffb1b fffffffffffffd60 fffffffffffffe9a ffffffffffffff43 ffffffffffffff9e ffffffffffffffce
	ffffffffffffffe7 fffffffffffffff4 fffffffffffffffb fffffffffffffffe
`

type cdtEntry struct{ upper, middle, lower uint32 }

var cdt []cdtEntry

func mustParseHex(text string, bitSize int) uint64 {
	value, err := strconv.ParseUint(text, 16, bitSize)
	if err != nil {
		panic("haetae: invalid CDT constant: " + text)
	}
	return value
}

func init() {
	highs, lows := strings.Fields(cdtHighText), strings.Fields(cdtLowText)
	cdt = make([]cdtEntry, len(lows))
	for i, text := range lows {
		low := mustParseHex(text, 64)
		high := uint64(0x7ffff)
		if i < len(highs) {
			high = mustParseHex(highs[i], 32)
		}
		cdt[i] = cdtEntry{uint32(high), uint32(low >> 32), uint32(low)}
	}
}
func sampleGaussian83(lower, middle, upper uint32) int {
	start, end := 0, len(cdt)
	for start < end {
		index := (start + end) >> 1
		t := cdt[index]
		isLower := t.upper < upper || (t.upper == upper && (t.middle < middle || (t.middle == middle && t.lower < lower)))
		if isLower {
			start = index + 1
		} else {
			end = index
		}
	}
	return start
}
func littleEndian48(bytes []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(bytes)) | uint64(binary.LittleEndian.Uint16(bytes[4:]))<<32
}
func gaussianCandidate(random []byte) (bool, uint64, fixed96) {
	gaussianLow := binary.LittleEndian.Uint32(random)
	gaussianMiddle := binary.LittleEndian.Uint32(random[4:])
	gaussianHigh := uint32(random[8]) | uint32(random[9])<<8 | uint32(random[10]&7)<<16
	rejection := littleEndian48(random[11:])
	x := sampleGaussian83(gaussianLow, gaussianMiddle, gaussianHigh)
	value := fixed96{littleEndian48(random[17:]), uint64(random[23]) | uint64(random[24])<<8 | uint64(random[25])<<16 | uint64(x)<<24}
	sample := ((value.low >> 15) + 1) >> 1
	sample += value.high << 32
	square := squareFixed(value)
	exponent := square.high - (uint64(x*x) << 20)
	exponent = (exponent << 20) | (square.low >> 28)
	exponent = (exponent + 1) >> 1
	even := rejection ^ (rejection & 1)
	accepted := even < approximateExponential(exponent) && (sample != 0 || rejection&1 != 0)
	return accepted, sample, square
}
func sampleGaussianN(seed []byte, nonce, length int, squareSum *fixed96) ([]uint64, []byte) {
	h := stream(256, seed, nonce)
	signs := make([]byte, length/8)
	h.Squeeze(signs)
	samples := make([]uint64, 0, length)
	var random [26]byte
	for len(samples) < length {
		h.Squeeze(random[:])
		accepted, sample, square := gaussianCandidate(random[:])
		if !accepted {
			continue
		}
		squareSum.low += square.low
		squareSum.high += square.high
		if len(samples) < n || length == n {
			samples = append(samples, sample)
		} else {
			samples = append(samples, 0)
		}
	}
	*squareSum = normalizeFixed(*squareSum)
	return samples[:n], signs
}

type hyperballSample struct {
	first, second polyVec
	bit           byte
	nextNonce     int
}

func sampleHyperball(p params, seed []byte, nonce int) hyperballSample {
	dimension := p.l + p.k
	spec := hyperSpecs[p.mode]
	normLimit := p.b0Squared * uint64(fixedScale*fixedScale)
	next := nonce
	for {
		squareSum := fixed96{}
		samples := make([][]uint64, dimension)
		signs := make([][]byte, dimension)
		for i := 0; i < dimension; i++ {
			length := n
			if i < 2 {
				length = n + 1
			}
			samples[i], signs[i] = sampleGaussianN(seed, next, length, &squareSum)
			next++
		}
		squareSum.low = (squareSum.low + 1) >> 1
		squareSum.low += (squareSum.high & 1) << 47
		squareSum.high >>= 1
		squareSum = normalizeFixed(squareSum)
		inverse := inverseSquareRoot(p.mode, squareSum)
		factor := multiplyFixedHigh(inverse, spec.scalar)
		fixed := zeroVector(dimension)
		for i := range fixed {
			for j := 0; j < n; j++ {
				fixed[i][j] = multiplyRound13(samples[i][j], factor, (signs[i][j>>3]>>uint(j&7))&1)
			}
		}
		first, second := fixed[:p.l], fixed[p.l:]
		if squaredNorm(first, second) <= normLimit {
			h := stream(256, seed, next)
			var b [1]byte
			h.Squeeze(b[:])
			return hyperballSample{first, second, b[0], next}
		}
	}
}
func roundFixed(value polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] = (out[i][j] + int32(fixedScale/2)) >> 13
		}
	}
	return out
}
func addFixedSignedInteger(fixed, integer polyVec, sign byte) polyVec {
	factor := int32(fixedScale)
	if sign != 0 {
		factor = -factor
	}
	out := cloneVector(fixed)
	for i := range out {
		for j := range out[i] {
			out[i][j] += factor * integer[i][j]
		}
	}
	return out
}
func doubleMinusFixedVectors(value, subtrahend polyVec) polyVec {
	out := cloneVector(value)
	for i := range out {
		for j := range out[i] {
			out[i][j] = 2*out[i][j] - subtrahend[i][j]
		}
	}
	return out
}
