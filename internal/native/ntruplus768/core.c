#define KPQC_VARIANT ntruplus768
#include "../common/ntruplus.h"
#include "../common/randombytes.h"
#include "../../../third_party/NTRUplus/NTRU+768/kem.c"
#include "../../../third_party/NTRUplus/NTRU+768/ntt.c"
#include "../../../third_party/NTRUplus/NTRU+768/poly.c"
#include "../../../third_party/NTRUplus/NTRU+768/symmetric.c"
#include "../../../third_party/NTRUplus/NTRU+768/fips202/fips202.c"
#define KPQC_GO_PREFIX kpqc_ntruplus768_
#include "../common/go_kem.h"
