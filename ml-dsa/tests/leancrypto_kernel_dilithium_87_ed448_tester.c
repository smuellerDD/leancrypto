#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#include "leancrypto_kernel_dilithium_87_ed448_tester_sig.c"
#else
#include "leancrypto_kernel_dilithium_87_ed448_tester_akcipher.c"
#endif
