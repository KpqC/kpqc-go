package haetae

const (
	n          = 256
	q          = int32(64513)
	doubleQ    = int32(129026)
	seedBytes  = 32
	crhBytes   = 64
	fixedScale = int64(8192)
)

type params struct {
	mode, k, l, m, tau                             int
	b0Squared, b1Squared, b2Squared                uint64
	gamma                                          float64
	baseEncodedHighZ1, baseEncodedHint             int
	alphaHint, logAlphaHint                        int32
	polyQBytes, poly2EtaBytes                      int
	publicKeyBytes, secretKeyBytes, signatureBytes int
}

func define(mode, k, l, tau int, b0, b1, b2, gamma float64, baseHigh, baseHint, alpha, polyQ, polyEta, sig int) params {
	m := l - 1
	pk := 32 + k*polyQ
	logAlpha := int32(9)
	if alpha == 256 {
		logAlpha = 8
	}
	return params{mode, k, l, m, tau, uint64(b0 * b0), uint64(b1 * b1), uint64(b2 * b2), gamma, baseHigh, baseHint, int32(alpha), logAlpha, polyQ, polyEta, pk, pk + m*64 + k*polyEta + 32, sig}
}

var (
	mode2 = define(2, 2, 4, 58, 9846.02, 9838.98, 12777.52, 48.858, 132, 7, 512, 480, 96, 1474)
	mode3 = define(3, 3, 6, 80, 18314.98, 18307.70, 21906.65, 57.707, 376, 127, 512, 480, 96, 2349)
	mode5 = define(5, 4, 7, 128, 22343.66, 22334.95, 24441.49, 55.13, 501, 358, 256, 512, 64, 2948)
)

type polynomial [n]int32
type polyVec []polynomial
type polyMatrix []polyVec

func zeroVector(length int) polyVec { return make(polyVec, length) }
func cloneVector(value polyVec) polyVec {
	output := make(polyVec, len(value))
	copy(output, value)
	return output
}
