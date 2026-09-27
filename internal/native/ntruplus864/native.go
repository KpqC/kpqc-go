package ntruplus864

/*
#cgo CFLAGS: -std=c11 -O2 -fvisibility=hidden -fno-strict-aliasing -I${SRCDIR}/../../../third_party/NTRUplus/NTRU+864
#cgo linux LDFLAGS: -lm
#cgo windows LDFLAGS: -lbcrypt
#include <stdint.h>
int kpqc_ntruplus864_keypair(uint8_t *, uint8_t *);
int kpqc_ntruplus864_encapsulate(uint8_t *, uint8_t *, const uint8_t *);
int kpqc_ntruplus864_decapsulate(uint8_t *, const uint8_t *, const uint8_t *);
*/
import "C"
import "unsafe"

func ptr(value []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&value[0])) }
func KeyPair(publicKey, secretKey []byte) int {
	return int(C.kpqc_ntruplus864_keypair(ptr(publicKey), ptr(secretKey)))
}
func Encapsulate(ciphertext, sharedSecret, publicKey []byte) int {
	return int(C.kpqc_ntruplus864_encapsulate(ptr(ciphertext), ptr(sharedSecret), ptr(publicKey)))
}
func Decapsulate(sharedSecret, ciphertext, secretKey []byte) int {
	return int(C.kpqc_ntruplus864_decapsulate(ptr(sharedSecret), ptr(ciphertext), ptr(secretKey)))
}
