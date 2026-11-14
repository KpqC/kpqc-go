//go:build kpqc_kat

package ntruplus

import "kpqc.dev/internal/portable/entropy"

func SetTestEntropy(input []byte) bool { return entropy.SetTestEntropy(input) }
func ClearTestEntropy() int            { return entropy.ClearTestEntropy() }
