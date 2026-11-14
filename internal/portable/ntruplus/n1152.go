package ntruplus

const n1152 = 1152

type arithmetic1152 struct{}

func (arithmetic1152) degree() int { return n1152 }

func (arithmetic1152) ntt(poly []int16) {
	k := 1
	zeta := zetas864[k]
	k++
	for i := 0; i < n1152/2; i++ {
		t := fqmul(zeta, poly[i+n1152/2])
		left, right := poly[i], poly[i+n1152/2]
		poly[i+n1152/2] = narrow(int32(left) + int32(right) - int32(t))
		poly[i] = narrow(int32(left) + int32(t))
	}
	for step := n1152 / 6; step >= 64; step /= 3 {
		for start := 0; start < n1152; start += 3 * step {
			zeta1, zeta2 := zetas864[k], zetas864[k+1]
			k += 2
			for i := start; i < start+step; i++ {
				t1 := fqmul(zeta1, poly[i+step])
				t2 := fqmul(zeta2, poly[i+2*step])
				t3 := fqmul(omega, narrow(int32(t1)-int32(t2)))
				base := poly[i]
				poly[i+2*step] = narrow(int32(base) - int32(t1) - int32(t3))
				poly[i+step] = narrow(int32(base) - int32(t2) + int32(t3))
				poly[i] = narrow(int32(base) + int32(t1) + int32(t2))
			}
		}
	}
	for step := 32; step >= 4; step >>= 1 {
		for start := 0; start < n1152; start += 2 * step {
			zeta := zetas864[k]
			k++
			for i := start; i < start+step; i++ {
				t := fqmul(zeta, poly[i+step])
				base := poly[i]
				poly[i+step] = barrettReduce(narrow(int32(base) - int32(t)))
				poly[i] = barrettReduce(narrow(int32(base) + int32(t)))
			}
		}
	}
}

func (arithmetic1152) inverseNTT(poly []int16) {
	k := 287
	for step := 4; step <= 32; step <<= 1 {
		for start := 0; start < n1152; start += 2 * step {
			zeta := zetas864[k]
			k--
			for i := start; i < start+step; i++ {
				t := poly[i+step]
				poly[i+step] = fqmul(zeta, narrow(int32(t)-int32(poly[i])))
				poly[i] = barrettReduce(narrow(int32(poly[i]) + int32(t)))
			}
		}
	}
	for step := 64; step <= n1152/6; step *= 3 {
		for start := 0; start < n1152; start += 3 * step {
			zeta2 := zetas864[k]
			k--
			zeta1 := zetas864[k]
			k--
			for i := start; i < start+step; i++ {
				a, b, c := poly[i], poly[i+step], poly[i+2*step]
				t1 := fqmul(omega, narrow(int32(b)-int32(a)))
				t2 := fqmul(zeta1, narrow(int32(c)-int32(a)+int32(t1)))
				t3 := fqmul(zeta2, narrow(int32(c)-int32(b)-int32(t1)))
				poly[i] = barrettReduce(narrow(int32(a) + int32(b) + int32(c)))
				poly[i+step], poly[i+2*step] = t2, t3
			}
		}
	}
	for i := 0; i < n1152/2; i++ {
		a, b := poly[i], poly[i+n1152/2]
		t1 := narrow(int32(a) + int32(b))
		t2 := fqmul(zMinusZ5Inv, narrow(int32(a)-int32(b)))
		poly[i] = fqmul(nInv864, narrow(int32(t1)-int32(t2)))
		poly[i+n1152/2] = fqmul(twoNInv864, t2)
	}
}

func (arithmetic1152) baseInverse(poly []int16) ([]int16, bool) {
	output := make([]int16, n1152)
	for i := 0; i < n1152/8; i++ {
		if !baseInverse4(output[8*i:8*i+4], poly[8*i:8*i+4], zetas864[144+i]) ||
			!baseInverse4(output[8*i+4:8*i+8], poly[8*i+4:8*i+8], -zetas864[144+i]) {
			return nil, false
		}
	}
	return output, true
}

func (arithmetic1152) baseMultiply(left, right []int16) []int16 {
	output := make([]int16, n1152)
	for i := 0; i < n1152/8; i++ {
		baseMultiply4(output[8*i:8*i+4], left[8*i:8*i+4], right[8*i:8*i+4], zetas864[144+i])
		baseMultiply4(output[8*i+4:8*i+8], left[8*i+4:8*i+8], right[8*i+4:8*i+8], -zetas864[144+i])
	}
	return output
}

func (a arithmetic1152) baseMultiplyAdd(left, right, addend []int16) []int16 {
	product := a.baseMultiply(left, right)
	output := make([]int16, n1152)
	addProduct(output, product, addend)
	return output
}
