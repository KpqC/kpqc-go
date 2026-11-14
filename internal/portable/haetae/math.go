package haetae

func montgomeryReduce(value int64) int32 {
	multiplier := int64(int32(value) * int32(940508161))
	return int32((value - multiplier*int64(q)) >> 32)
}

func freeze(value int32) int32 {
	result := value % q
	if result < 0 {
		result += q
	}
	return result
}
func centeredMod2Q(value int32) int32 {
	result := value % doubleQ
	if result < -q {
		result += doubleQ
	}
	if result >= q {
		result -= doubleQ
	}
	return result
}
func freeze2Q(value int32) int32 {
	result := value % doubleQ
	if result < 0 {
		result += doubleQ
	}
	return result
}

func decomposeZ1(value int32) (int32, int32) {
	low := value & 255
	if low >= 128 {
		low -= 256
	}
	return (value + 128) >> 8, low
}
func decomposeHint(value, alpha, logAlpha int32) int32 {
	high := (value + alpha/2) >> logAlpha
	if high == (doubleQ-2)/alpha {
		high = 0
	}
	return high
}
func decomposePublicKey(value int32) (int32, int32) {
	low := value & 1
	low -= ((value >> 1) & low) << 1
	return (value - low) >> 1, low
}

func squaredNorm(groups ...polyVec) uint64 {
	var sum uint64
	for _, group := range groups {
		for i := range group {
			for _, coefficient := range group[i] {
				value := int64(coefficient)
				sum += uint64(value * value)
			}
		}
	}
	return sum
}
