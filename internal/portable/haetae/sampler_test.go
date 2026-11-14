package haetae

import (
	"math/big"
	"testing"
)

func referenceSignedMultiplyHigh48(left int64, right uint64) int64 {
	product := new(big.Int).Mul(big.NewInt(left), new(big.Int).SetUint64(right))
	product.Add(product, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 48), big.NewInt(1)))
	product.Rsh(product, 48)
	return product.Int64()
}

func TestSignedMultiplyHigh48(t *testing.T) {
	leftValues := []int64{
		-281474976710650,
		-46912496106200,
		-1,
		0,
		1,
		55868746,
		281474976710657,
	}
	rightValues := []uint64{
		0,
		1,
		(1 << 48) - 1,
		1 << 48,
		(1 << 49) - 1,
	}

	for _, left := range leftValues {
		for _, right := range rightValues {
			got := signedMultiplyHigh48(left, right)
			want := referenceSignedMultiplyHigh48(left, right)
			if got != want {
				t.Fatalf("signedMultiplyHigh48(%d, %d) = %d, want %d", left, right, got, want)
			}
		}
	}
}
