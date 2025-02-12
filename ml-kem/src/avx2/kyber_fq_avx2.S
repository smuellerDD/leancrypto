#include "assembler_support.h"
#include "kyber_type.h"
#include "kyber_consts_avx2.h"
#include "kyber_fq_avx2.inc"

.macro reduce128_avx
#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

red16		2
red16		3
red16		4
red16		5
red16		6
red16		7
red16		8
red16		9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
.endm

.macro tomont128_avx
#load
vmovdqa		(%rdi),%ymm3
vmovdqa		32(%rdi),%ymm4
vmovdqa		64(%rdi),%ymm5
vmovdqa		96(%rdi),%ymm6
vmovdqa		128(%rdi),%ymm7
vmovdqa		160(%rdi),%ymm8
vmovdqa		192(%rdi),%ymm9
vmovdqa		224(%rdi),%ymm10

fqmulprecomp	1,2,3,11
fqmulprecomp	1,2,4,12
fqmulprecomp	1,2,5,13
fqmulprecomp	1,2,6,14
fqmulprecomp	1,2,7,15
fqmulprecomp	1,2,8,11
fqmulprecomp	1,2,9,12
fqmulprecomp	1,2,10,13

#store
vmovdqa		%ymm3,(%rdi)
vmovdqa		%ymm4,32(%rdi)
vmovdqa		%ymm5,64(%rdi)
vmovdqa		%ymm6,96(%rdi)
vmovdqa		%ymm7,128(%rdi)
vmovdqa		%ymm8,160(%rdi)
vmovdqa		%ymm9,192(%rdi)
vmovdqa		%ymm10,224(%rdi)
.endm

.text
SYM_FUNC_START(reduce_avx)
#consts
vmovdqa		_16XQ*2(%rsi),%ymm0
vmovdqa		_16XV*2(%rsi),%ymm1
reduce128_avx
add		$256,%rdi
reduce128_avx
RET
SYM_FUNC_END(reduce_avx)

SYM_FUNC_START(tomont_avx)
#consts
vmovdqa		_16XQ*2(%rsi),%ymm0
vmovdqa		_16XMONTSQLO*2(%rsi),%ymm1
vmovdqa		_16XMONTSQHI*2(%rsi),%ymm2
tomont128_avx
add		$256,%rdi
tomont128_avx
RET
SYM_FUNC_END(tomont_avx)

ASM_END
