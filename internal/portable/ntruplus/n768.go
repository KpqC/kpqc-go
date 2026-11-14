package ntruplus

const (
	n768         = 768
	nInv768      = -811
	twoNInv768   = -1622
	polyBytes768 = 1152
)

var zetas768 = [192]int16{
	-147, -1033, -682, -248, -708, 682, 1, -722, -723, -257, -1124, -867, -256, 1484, 1262, -1590,
	1611, 222, 1164, -1346, 1716, -1521, -357, 395, -455, 639, 502, 655, -699, 541, 95, -1577,
	-1241, 550, -44, 39, -820, -216, -121, -757, -348, 937, 893, 387, -603, 1713, -1105, 1058,
	1449, 837, 901, 1637, -569, -1617, -1530, 1199, 50, -830, -625, 4, 176, -156, 1257, -1507,
	-380, -606, 1293, 661, 1428, -1580, -565, -992, 548, -800, 64, -371, 961, 641, 87, 630, 675,
	-834, 205, 54, -1081, 1351, 1413, -1331, -1673, -1267, -1558, 281, -1464, -588, 1015, 436, 223,
	1138, -1059, -397, -183, 1655, 559, -1674, 277, 933, 1723, 437, -1514, 242, 1640, 432, -1583,
	696, 774, 1671, 927, 514, 512, 489, 297, 601, 1473, 1130, 1322, 871, 760, 1212, -312, -352,
	443, 943, 8, 1250, -100, 1660, -31, 1206, -1341, -1247, 444, 235, 1364, -1209, 361, 230, 673,
	582, 1409, 1501, 1401, 251, 1022, -1063, 1053, 1188, 417, -1391, -27, -1626, 1685, -315, 1408,
	-1248, 400, 274, -1543, 32, -1550, 1531, -1367, -124, 1458, 1379, -940, -1681, 22, 1709, -275,
	1108, 354, -1728, -968, 858, 1221, -218, 294, -732, -1095, 892, 1588, -779,
}

type arithmetic768 struct{}

func (arithmetic768) degree() int { return n768 }

func (arithmetic768) ntt(poly []int16) {
	k := 1
	zeta := zetas768[k]
	k++
	for i := 0; i < n768/2; i++ {
		t := fqmul(zeta, poly[i+n768/2])
		left, right := poly[i], poly[i+n768/2]
		poly[i+n768/2] = narrow(int32(left) + int32(right) - int32(t))
		poly[i] = narrow(int32(left) + int32(t))
	}
	for start := 0; start < n768; start += 384 {
		zeta1, zeta2 := zetas768[k], zetas768[k+1]
		k += 2
		for i := start; i < start+128; i++ {
			t1 := fqmul(zeta1, poly[i+128])
			t2 := fqmul(zeta2, poly[i+256])
			t3 := fqmul(omega, narrow(int32(t1)-int32(t2)))
			base := poly[i]
			poly[i+256] = narrow(int32(base) - int32(t1) - int32(t3))
			poly[i+128] = narrow(int32(base) - int32(t2) + int32(t3))
			poly[i] = narrow(int32(base) + int32(t1) + int32(t2))
		}
	}
	for step := 64; step >= 4; step >>= 1 {
		for start := 0; start < n768; start += 2 * step {
			zeta := zetas768[k]
			k++
			for i := start; i < start+step; i++ {
				t := fqmul(zeta, poly[i+step])
				base := poly[i]
				poly[i+step] = narrow(int32(base) - int32(t))
				poly[i] = narrow(int32(base) + int32(t))
			}
		}
	}
	for i := range poly {
		poly[i] = barrettReduce(poly[i])
	}
}

func (arithmetic768) inverseNTT(poly []int16) {
	k := 191
	for step := 4; step <= 64; step <<= 1 {
		for start := 0; start < n768; start += 2 * step {
			zeta := zetas768[k]
			k--
			for i := start; i < start+step; i++ {
				t := poly[i+step]
				poly[i+step] = fqmul(zeta, narrow(int32(t)-int32(poly[i])))
				poly[i] = barrettReduce(narrow(int32(poly[i]) + int32(t)))
			}
		}
	}
	for start := 0; start < n768; start += 384 {
		zeta2 := zetas768[k]
		k--
		zeta1 := zetas768[k]
		k--
		for i := start; i < start+128; i++ {
			a, b, c := poly[i], poly[i+128], poly[i+256]
			t1 := fqmul(omega, narrow(int32(b)-int32(a)))
			t2 := fqmul(zeta1, narrow(int32(c)-int32(a)+int32(t1)))
			t3 := fqmul(zeta2, narrow(int32(c)-int32(b)-int32(t1)))
			poly[i] = narrow(int32(a) + int32(b) + int32(c))
			poly[i+128], poly[i+256] = t2, t3
		}
	}
	for i := 0; i < n768/2; i++ {
		a, b := poly[i], poly[i+n768/2]
		t1 := narrow(int32(a) + int32(b))
		t2 := fqmul(zMinusZ5Inv, narrow(int32(a)-int32(b)))
		poly[i] = fqmul(nInv768, narrow(int32(t1)-int32(t2)))
		poly[i+n768/2] = fqmul(twoNInv768, t2)
	}
}

func (arithmetic768) baseInverse(poly []int16) ([]int16, bool) {
	output := make([]int16, n768)
	for i := 0; i < n768/8; i++ {
		if !baseInverse4(output[8*i:8*i+4], poly[8*i:8*i+4], zetas768[96+i]) ||
			!baseInverse4(output[8*i+4:8*i+8], poly[8*i+4:8*i+8], -zetas768[96+i]) {
			return nil, false
		}
	}
	return output, true
}

func (arithmetic768) baseMultiply(left, right []int16) []int16 {
	output := make([]int16, n768)
	for i := 0; i < n768/8; i++ {
		baseMultiply4(output[8*i:8*i+4], left[8*i:8*i+4], right[8*i:8*i+4], zetas768[96+i])
		baseMultiply4(output[8*i+4:8*i+8], left[8*i+4:8*i+8], right[8*i+4:8*i+8], -zetas768[96+i])
	}
	return output
}

func (a arithmetic768) baseMultiplyAdd(left, right, addend []int16) []int16 {
	product := a.baseMultiply(left, right)
	output := make([]int16, n768)
	addProduct(output, product, addend)
	return output
}
