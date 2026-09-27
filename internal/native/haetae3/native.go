package haetae3

/*
#cgo CFLAGS: -std=c11 -O2 -fvisibility=hidden -fno-strict-aliasing -I${SRCDIR}/../../../third_party/HAETAE/include
#cgo linux LDFLAGS: -lm
#cgo windows LDFLAGS: -lbcrypt
#include <stddef.h>
#include <stdint.h>
int kpqc_haetae3_keypair(uint8_t *, uint8_t *);
int kpqc_haetae3_sign(uint8_t *, uint64_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
int kpqc_haetae3_verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
*/
import "C"
import "unsafe"

var zero byte

func ptr(value []byte) *C.uint8_t {
	if len(value) == 0 {
		return (*C.uint8_t)(unsafe.Pointer(&zero))
	}
	return (*C.uint8_t)(unsafe.Pointer(&value[0]))
}
func KeyPair(publicKey, secretKey []byte) int {
	return int(C.kpqc_haetae3_keypair(ptr(publicKey), ptr(secretKey)))
}
func Sign(signature []byte, length *uint64, message, context, secretKey []byte) int {
	return int(C.kpqc_haetae3_sign(ptr(signature), (*C.uint64_t)(unsafe.Pointer(length)), ptr(message), C.size_t(len(message)), ptr(context), C.size_t(len(context)), ptr(secretKey)))
}
func Verify(signature, message, context, publicKey []byte) int {
	return int(C.kpqc_haetae3_verify(ptr(signature), C.size_t(len(signature)), ptr(message), C.size_t(len(message)), ptr(context), C.size_t(len(context)), ptr(publicKey)))
}
