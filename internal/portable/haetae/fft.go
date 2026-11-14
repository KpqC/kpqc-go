package haetae

import (
	"sort"
)

var rootReal, rootImaginary [n]int64
var reversedIndices [n]byte

var rootQuarter = [...][2]int64{
	{65536, 0}, {65531, -804}, {65516, -1608}, {65492, -2412},
	{65457, -3216}, {65413, -4019}, {65358, -4821}, {65294, -5623},
	{65220, -6424}, {65137, -7224}, {65043, -8022}, {64940, -8820},
	{64827, -9616}, {64704, -10411}, {64571, -11204}, {64429, -11996},
	{64277, -12785}, {64115, -13573}, {63944, -14359}, {63763, -15143},
	{63572, -15924}, {63372, -16703}, {63162, -17479}, {62943, -18253},
	{62714, -19024}, {62476, -19792}, {62228, -20557}, {61971, -21320},
	{61705, -22078}, {61429, -22834}, {61145, -23586}, {60851, -24335},
	{60547, -25080}, {60235, -25821}, {59914, -26558}, {59583, -27291},
	{59244, -28020}, {58896, -28745}, {58538, -29466}, {58172, -30182},
	{57798, -30893}, {57414, -31600}, {57022, -32303}, {56621, -33000},
	{56212, -33692}, {55794, -34380}, {55368, -35062}, {54934, -35738},
	{54491, -36410}, {54040, -37076}, {53581, -37736}, {53114, -38391},
	{52639, -39040}, {52156, -39683}, {51665, -40320}, {51166, -40951},
	{50660, -41576}, {50146, -42194}, {49624, -42806}, {49095, -43412},
	{48559, -44011}, {48015, -44604}, {47464, -45190}, {46906, -45769},
	{46341, -46341},
}

func init() {
	for i, root := range rootQuarter {
		rootReal[i], rootImaginary[i] = root[0], root[1]
	}
	for i := len(rootQuarter); i <= n/2; i++ {
		mirrored := n/2 - i
		rootReal[i], rootImaginary[i] = -rootImaginary[mirrored], -rootReal[mirrored]
	}
	for i := n/2 + 1; i < n; i++ {
		mirrored := n - i
		rootReal[i], rootImaginary[i] = -rootReal[mirrored], rootImaginary[mirrored]
	}
	for i := 0; i < n; i++ {
		reversedIndices[i] = reverseBits8(byte(i))
	}
}
func reverseBits8(value byte) byte {
	var result byte
	for bit := 0; bit < 8; bit++ {
		result = result<<1 | ((value >> bit) & 1)
	}
	return result
}
func roundedShift16(value int64) int64       { return (value + 32768) >> 16 }
func roundedSquareShift16(value int64) int64 { return (value*value + 32768) >> 16 }

func fftTransform(input *polynomial) ([n]int64, [n]int64) {
	var real, imaginary [n]int64
	for i := 0; i < n; i++ {
		reversed := reversedIndices[i]
		real[reversed] = int64(input[i]) * rootReal[i]
		imaginary[reversed] = int64(input[i]) * rootImaginary[i]
	}
	for round := 1; round <= 8; round++ {
		width := 1 << round
		half := width >> 1
		for start := 0; start < n; start += width {
			for offset := 0; offset < half; offset++ {
				even := start + offset
				odd := even + half
				rootIndex := offset << (9 - round)
				rootR, rootI := rootReal[rootIndex], rootImaginary[rootIndex]
				oddR, oddI := real[odd], imaginary[odd]
				rightR := roundedShift16(rootR*oddR) - roundedShift16(rootI*oddI)
				rightI := roundedShift16(rootR*oddI) + roundedShift16(rootI*oddR)
				leftR, leftI := real[even], imaginary[even]
				real[even], imaginary[even] = leftR+rightR, leftI+rightI
				real[odd], imaginary[odd] = leftR-rightR, leftI-rightI
			}
		}
	}
	return real, imaginary
}
func secretSingularValue(p params, first, second polyVec) int64 {
	sums := make([]int64, n)
	for _, group := range []polyVec{first, second} {
		for i := range group {
			real, imaginary := fftTransform(&group[i])
			for j := 0; j < n; j++ {
				sums[j] += roundedSquareShift16(real[j]) + roundedSquareShift16(imaginary[j])
			}
		}
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i] > sums[j] })
	selectedCount := n/p.tau + 1
	minimum := sums[selectedCount-1]
	var result int64
	for _, value := range sums[:selectedCount] {
		factor := p.tau
		if value == minimum {
			factor = n % p.tau
		}
		result += ((value + 0x10200) / 1024) * int64(factor)
	}
	return (result + 32) / 64
}
