//go:build kpqc_kat

package smaugt

import "kpqc.dev/internal/portable/entropy"

func SetTestEntropy(input []byte) bool { return entropy.SetTestEntropy(input) }
func ClearTestEntropy() int            { return entropy.ClearTestEntropy() }
