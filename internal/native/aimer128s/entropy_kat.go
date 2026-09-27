//go:build kpqc_kat

package aimer128s

/*
#cgo CFLAGS: -DKPQC_TEST_ENTROPY=1
#include <stddef.h>
#include <stdint.h>
int kpqc_aimer128s_set_test_entropy(const uint8_t *, size_t);
size_t kpqc_aimer128s_test_entropy_remaining(void);
void kpqc_aimer128s_clear_test_entropy(void);
*/
import "C"

func SetTestEntropy(entropy []byte) bool {
	return C.kpqc_aimer128s_set_test_entropy(ptr(entropy), C.size_t(len(entropy))) == 0
}

func ClearTestEntropy() int {
	remaining := int(C.kpqc_aimer128s_test_entropy_remaining())
	C.kpqc_aimer128s_clear_test_entropy()
	return remaining
}
