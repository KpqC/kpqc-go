package ntruplus

const (
	n864              = 864
	omega       int16 = -886
	zMinusZ5Inv int16 = -1665
	nInv864     int16 = -1693
	twoNInv864  int16 = 71
)

var zetas864 = [288]int16{
	-147, -1033, -1265, 708, 460, 1265, -467, 727, 556, 1307, -773, -161, 1200, -1612, 570, 1529,
	1135, -556, 1120, 298, -822, -1556, -93, 1463, 532, -377, -909, 58, -392, -450, 1722, 1236,
	-486, -491, -1569, -1078, 36, 1289, -1443, 1628, 1664, -725, -952, 99, -1020, 353, -599, 1119,
	592, 839, 1622, 652, 1244, -783, -1085, -726, 566, -284, -1369, -1292, 268, -391, 781, -172,
	96, -1172, 211, 737, 473, -445, -234, 264, -1536, 1467, -676, -1542, -170, 635, -705, -1332,
	-658, 831, -1712, 1311, 1488, -881, 1087, -1315, 1245, -75, 791, -6, -875, -697, -70, -1162,
	287, -767, -945, 1598, -882, 1261, 206, 654, -1421, -81, 716, -1251, 838, -1300, 1035, -104,
	966, -558, -61, -1704, 404, -899, 862, -1593, -1460, -37, 1266, 965, -1584, -1404, -265, -942,
	905, 1195, -619, 787, 118, 576, 286, -1475, -194, 928, 1229, -1032, 1608, 1111, -1669, 642,
	-1323, 163, 309, 981, -557, -258, 232, -1680, -1657, -1233, 144, 1699, 311, -1060, 578, 1298,
	-403, 1607, 1074, -148, 447, -1568, 1142, -402, -1412, -623, 855, 365, -98, -244, 407, 1225,
	416, 683, -105, 1714, -1019, 1061, 1163, 638, 798, 1493, -351, 396, -542, -9, 1616, -139, -987,
	-482, 889, 238, -1513, 466, -1089, -101, 849, -426, 1589, 1487, 671, 1459, -776, 255, -1014,
	1144, 472, -1153, -325, 1519, -26, -1123, 324, 1230, 1547, -593, -428, 1192, 1072, -1564, 688,
	-333, 1023, -1686, 841, 824, -71, 1587, 522, -323, 1148, 389, 1231, 384, 1343, 169, 628, -1329,
	-1056, -936, 24, -293, 1523, -300, -1654, 891, -962, -67, 179, -1177, 844, -509, -1677, -1565,
	-549, -1508, 1191, -280, -43, 669, -746, 753, 770, -1046, 1711, 1438, 690, 1083, 1062, 1727,
	-883, 553, 1670, 66, 825, -133, -1586, 637, -680, -917, 644, -372, -1193, -1136,
}

type arithmetic864 struct{}

func (arithmetic864) degree() int { return n864 }

func (arithmetic864) ntt(poly []int16) {
	k := 1
	zeta := zetas864[k]
	k++
	for i := 0; i < n864/2; i++ {
		t := fqmul(zeta, poly[i+n864/2])
		left, right := poly[i], poly[i+n864/2]
		poly[i+n864/2] = narrow(int32(left) + int32(right) - int32(t))
		poly[i] = narrow(int32(left) + int32(t))
	}
	for step := n864 / 6; step >= 48; step /= 3 {
		for start := 0; start < n864; start += 3 * step {
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
	for step := 24; step >= 3; step >>= 1 {
		for start := 0; start < n864; start += 2 * step {
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

func (arithmetic864) inverseNTT(poly []int16) {
	k := 287
	for step := 3; step <= 24; step <<= 1 {
		for start := 0; start < n864; start += 2 * step {
			zeta := zetas864[k]
			k--
			for i := start; i < start+step; i++ {
				t := poly[i+step]
				poly[i+step] = fqmul(zeta, narrow(int32(t)-int32(poly[i])))
				poly[i] = barrettReduce(narrow(int32(poly[i]) + int32(t)))
			}
		}
	}
	for step := 48; step <= n864/6; step *= 3 {
		for start := 0; start < n864; start += 3 * step {
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
	for i := 0; i < n864/2; i++ {
		a, b := poly[i], poly[i+n864/2]
		t1 := narrow(int32(a) + int32(b))
		t2 := fqmul(zMinusZ5Inv, narrow(int32(a)-int32(b)))
		poly[i] = fqmul(nInv864, narrow(int32(t1)-int32(t2)))
		poly[i+n864/2] = fqmul(twoNInv864, t2)
	}
}

func (arithmetic864) baseInverse(poly []int16) ([]int16, bool) {
	output := make([]int16, n864)
	for i := 0; i < n864/6; i++ {
		if !baseInverse3(output[6*i:6*i+3], poly[6*i:6*i+3], zetas864[144+i]) ||
			!baseInverse3(output[6*i+3:6*i+6], poly[6*i+3:6*i+6], -zetas864[144+i]) {
			return nil, false
		}
	}
	return output, true
}

func (arithmetic864) baseMultiply(left, right []int16) []int16 {
	output := make([]int16, n864)
	for i := 0; i < n864/6; i++ {
		baseMultiply3(output[6*i:6*i+3], left[6*i:6*i+3], right[6*i:6*i+3], zetas864[144+i])
		baseMultiply3(output[6*i+3:6*i+6], left[6*i+3:6*i+6], right[6*i+3:6*i+6], -zetas864[144+i])
	}
	return output
}

func (a arithmetic864) baseMultiplyAdd(left, right, addend []int16) []int16 {
	product := a.baseMultiply(left, right)
	output := make([]int16, n864)
	addProduct(output, product, addend)
	return output
}
