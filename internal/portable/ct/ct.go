// Package ct provides the small constant-time operations used by the ports.
package ct

func Equal(left, right []byte) byte {
	if len(left) != len(right) {
		return 0
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return ((difference | -difference) >> 7) ^ 1
}

func Select(output, whenZero, whenOne []byte, choice byte) {
	if len(output) != len(whenZero) || len(output) != len(whenOne) {
		panic("ct: mismatched buffer lengths")
	}
	mask := byte(0) - (choice & 1)
	for i := range output {
		output[i] = whenZero[i]&^mask | whenOne[i]&mask
	}
}
