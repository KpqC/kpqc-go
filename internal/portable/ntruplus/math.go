package ntruplus

const (
	q        int16 = 3457
	r        int16 = -147
	rInv     int16 = -682
	rSquared int16 = 867
	qInv     int16 = 12929
)

func narrow(value int32) int16 { return int16(value) }

func montgomeryReduce(value int32) int16 {
	low := int32(narrow(value))
	t := narrow(low * int32(qInv))
	return narrow((value - int32(t)*int32(q)) >> 16)
}

func barrettReduce(value int16) int16 {
	const v int32 = ((1 << 26) + int32(q)/2) / int32(q)
	t := (v*int32(value) + (1 << 25)) >> 26
	t *= int32(q)
	return narrow(int32(value) - t)
}

func fqmul(left, right int16) int16 {
	return montgomeryReduce(int32(left) * int32(right))
}

func fqinv(value int16) int16 {
	t0 := fqmul(value, value)
	t0 = fqmul(t0, t0)
	t0 = fqmul(t0, t0)
	t0 = fqmul(t0, t0)
	t1 := fqmul(t0, value)
	t0 = fqmul(t0, t0)
	t0 = fqmul(t0, t0)
	t0 = fqmul(t0, t0)
	t1 = fqmul(t0, t1)
	t0 = fqmul(t1, t0)
	t1 = fqmul(t0, t1)
	t1 = fqmul(t1, t0)
	t0 = fqmul(t1, t1)
	t0 = fqmul(t0, t0)
	t0 = fqmul(t0, t1)
	return fqmul(rInv, t0)
}

func baseInverse3(output, input []int16, zeta int16) bool {
	output[0] = montgomeryReduce(int32(input[1]) * int32(input[2]))
	output[1] = montgomeryReduce(int32(input[2]) * int32(input[2]))
	output[2] = montgomeryReduce(int32(input[1])*int32(input[1]) - int32(input[0])*int32(input[2]))
	output[0] = montgomeryReduce(int32(input[0])*int32(input[0]) - int32(output[0])*int32(zeta))
	output[1] = montgomeryReduce(int32(output[1])*int32(zeta) - int32(input[0])*int32(input[1]))
	inverse := montgomeryReduce(int32(output[2])*int32(input[1]) + int32(output[1])*int32(input[2]))
	inverse = montgomeryReduce(int32(inverse)*int32(zeta) + int32(output[0])*int32(input[0]))
	if inverse == 0 {
		return false
	}
	inverse = fqinv(inverse)
	for i := 0; i < 3; i++ {
		output[i] = montgomeryReduce(int32(output[i]) * int32(inverse))
	}
	return true
}

func baseMultiply3(output, left, right []int16, zeta int16) {
	t0 := montgomeryReduce(int32(left[2])*int32(right[1]) + int32(left[1])*int32(right[2]))
	t1 := montgomeryReduce(int32(left[2]) * int32(right[2]))
	c0 := montgomeryReduce(int32(t0)*int32(zeta) + int32(left[0])*int32(right[0]))
	c1 := montgomeryReduce(int32(t1)*int32(zeta) + int32(left[0])*int32(right[1]) + int32(left[1])*int32(right[0]))
	c2 := montgomeryReduce(int32(left[2])*int32(right[0]) + int32(left[1])*int32(right[1]) + int32(left[0])*int32(right[2]))
	for i, value := range [...]int16{c0, c1, c2} {
		output[i] = montgomeryReduce(int32(value) * int32(rSquared))
	}
}

func baseInverse4(output, input []int16, zeta int16) bool {
	t0 := montgomeryReduce(int32(input[2])*int32(input[2]) - 2*int32(input[1])*int32(input[3]))
	t1 := montgomeryReduce(int32(input[3]) * int32(input[3]))
	t0 = montgomeryReduce(int32(input[0])*int32(input[0]) + int32(t0)*int32(zeta))
	t1 = montgomeryReduce(int32(input[1])*int32(input[1]) + int32(t1)*int32(zeta) - 2*int32(input[0])*int32(input[2]))
	t2 := montgomeryReduce(int32(t1) * int32(zeta))
	inverse := montgomeryReduce(int32(t0)*int32(t0) - int32(t1)*int32(t2))
	if inverse == 0 {
		return false
	}
	output[0] = montgomeryReduce(int32(input[0])*int32(t0) + int32(input[2])*int32(t2))
	output[1] = montgomeryReduce(int32(input[3])*int32(t2) + int32(input[1])*int32(t0))
	output[2] = montgomeryReduce(int32(input[2])*int32(t0) + int32(input[0])*int32(t1))
	output[3] = montgomeryReduce(int32(input[1])*int32(t1) + int32(input[3])*int32(t0))
	inverse = fqinv(inverse)
	output[0] = montgomeryReduce(int32(output[0]) * int32(inverse))
	output[1] = -montgomeryReduce(int32(output[1]) * int32(inverse))
	output[2] = montgomeryReduce(int32(output[2]) * int32(inverse))
	output[3] = -montgomeryReduce(int32(output[3]) * int32(inverse))
	return true
}

func baseMultiply4(output, left, right []int16, zeta int16) {
	t0 := montgomeryReduce(int32(left[1])*int32(right[3]) + int32(left[2])*int32(right[2]) + int32(left[3])*int32(right[1]))
	t1 := montgomeryReduce(int32(left[2])*int32(right[3]) + int32(left[3])*int32(right[2]))
	t2 := montgomeryReduce(int32(left[3]) * int32(right[3]))
	c0 := montgomeryReduce(int32(t0)*int32(zeta) + int32(left[0])*int32(right[0]))
	c1 := montgomeryReduce(int32(t1)*int32(zeta) + int32(left[0])*int32(right[1]) + int32(left[1])*int32(right[0]))
	c2 := montgomeryReduce(int32(t2)*int32(zeta) + int32(left[0])*int32(right[2]) + int32(left[1])*int32(right[1]) + int32(left[2])*int32(right[0]))
	c3 := montgomeryReduce(int32(left[0])*int32(right[3]) + int32(left[1])*int32(right[2]) + int32(left[2])*int32(right[1]) + int32(left[3])*int32(right[0]))
	for i, value := range [...]int16{c0, c1, c2, c3} {
		output[i] = montgomeryReduce(int32(value) * int32(rSquared))
	}
}

func addProduct(output, product, addend []int16) {
	for i := range output {
		output[i] = montgomeryReduce(int32(addend[i])*int32(r) + int32(product[i])*int32(r))
	}
}
