/* ARMv8 implementation of CBD functions */

#include "assembler_support.h"
#include "kyber_type.h"

/*************************************************	
*	Macro Name:		MCBD2
*	Description:	Vectorized noise sampling for eta = 2
*					- It produces four vectors vc0, vc1, vc2, vc3
*					for a given vector va.
*	Arguments:		va.16b = [a0, a1, ..., a15], 
*					v0 as vm0.16b = [0x55, ..., 0x55],
*					v1 as vm1.16b = [0x33, ..., 0x33],
*					v2 as vm2.16b = [0x03, ..., 0x03],
*					v3 as vm3.16b = [0x0F, ..., 0x0F]
*					vc0.8h = [c00, c01, ..., c07]
*					vc1.8h = [c10, c11, ..., c17]
*					vc2.8h = [c20, c21, ..., c27]
*					vc3.8h = [c30, c31, ..., c37]
*	Intermediate Values/Vectors:
*					v4 as vd, 
*					v5 as ve,
*					v6 as vf
**************************************************/
.macro mcbd2 a, c0, c1, c2, c3
	// f0 = a 
	ushr 	v4.8h, v\a\().8h, 1					// f1 = f0 >> 1
	and		v\a\().16b, v\a\().16b, v0.16b		// f0 = f0 & 55
	and		v4.16b, v4.16b, v0.16b				// f1 = f1 & 55
	add		v\a\().16b, v\a\().16b, v4.16b		// f0 = f0 + f1

	ushr 	v4.8h, v\a\().8h, 2					// f1 = f0 >> 2
	and		v\a\().16b, v\a\().16b, v1.16b		// f0 = f0 & 33
	and		v4.16b, v4.16b, v1.16b				// f1 = f1 & 33
	add		v\a\().16b, v\a\().16b, v1.16b		// f0 = f0 + 33
	sub		v\a\().16b, v\a\().16b, v4.16b		// f0 = f0 - f1

	ushr 	v4.8h, v\a\().8h, 4					// f1 = f0 >> 4
	and		v\a\().16b, v\a\().16b, v3.16b			// f0 = f0 & 0F
	and		v4.16b, v4.16b, v3.16b				// f1 = f1 & 0F
	sub		v\a\().16b, v\a\().16b, v2.16b		// f0 = f0 - 03
	sub		v4.16b, v4.16b, v2.16b				// f1 = f1 - 03

	zip1	v5.16b, v\a\().16b, v4.16b
	zip2	v6.16b, v\a\().16b, v4.16b

	sxtl	v\c0\().8h, v5.8b
	sxtl2	v\c1\().8h, v5.16b
	sxtl	v\c2\().8h, v6.8b
	sxtl2	v\c3\().8h, v6.16b

.endm

/*************************************************
*	Function Name:	kyber_cbd2_armv8
*	Description:	Given an array of uniformly random bytes, compute
*					polynomial with coefficients distributed according to
*					a centered binomial distribution with parameter eta=2
*	Corresponds to:	void kyber_cbd2_armv8(poly *r, const uint8_t *buf);
*	Arguments:		x0 as poly *r
*					x1 as const uint8_t *buf
*	Notes:			- Masking values are loaded to the vectors v0-v3
*					- (1st/2nd Half of) Buf values are loaded to the vectors v12-v15
*					- (1st/2nd Half of) R values are stored from the vectors v16-v31
*					- The vectors v4-v6 are registered for the intermediate values in the macro "mcbd2"
*					- The function is completed in two parts (because of the limited number of vectors)
**************************************************/
SYM_FUNC_START(kyber_cbd2_armv8)
SYM_FUNC_ENTER(kyber_cbd2_armv8)
.align	4
	// Load the masking values to v0 - v3
	movi	v0.16b, #0x55
	movi	v1.16b, #0x33
	movi	v2.16b, #0x03
	movi	v3.16b, #0x0F

	// Load buf values, CBD2 Computations, store r values (part 1)
	ld1   	{v12.16b-v15.16b}, [x1], #64

	mcbd2 12, 16, 17, 18, 19
	mcbd2 13, 20, 21, 22, 23
	mcbd2 14, 24, 25, 26, 27
	mcbd2 15, 28, 29, 30, 31
	
	st1 {v16.8h-v19.8h}, [x0], #64
	st1 {v20.8h-v23.8h}, [x0], #64
	st1 {v24.8h-v27.8h}, [x0], #64
	st1 {v28.8h-v31.8h}, [x0], #64

	// Load buf values, CBD2 Computations, store r values (part 2)
	ld1   	{v12.16b-v15.16b}, [x1], #64

	mcbd2 12, 16, 17, 18, 19
	mcbd2 13, 20, 21, 22, 23
	mcbd2 14, 24, 25, 26, 27
	mcbd2 15, 28, 29, 30, 31
	
	st1 {v16.8h-v19.8h}, [x0], #64
	st1 {v20.8h-v23.8h}, [x0], #64
	st1 {v24.8h-v27.8h}, [x0], #64
	st1 {v28.8h-v31.8h}, [x0], #64
	
	//
	RET
SYM_FUNC_END(kyber_cbd2_armv8)

/*************************************************
*	Macro Name:		MCBD3
*	Description:	Vectorized noise sampling for eta = 3
*					- It produces two vectors vc0 and vc1
*					for a given vector va.
*   Arguments:		va.16b = [a0, a1, ..., a15], 
*					v0 as vs.16b = [−1, 11, 10, 9, −1, 8, 7, 6, −1, 5, 4, 3, −1, 2, 1, 0], (shuffle)
*					v1 as vm0.4s = [0x00249249, ...],
*					v2 as vm1.4s = [0x006DB6DB, ...]
*					v3 as vm2.16b = [0x00000007, ...],
*					v4 as vm3.16b = [0x00070000, ...],
*					v5 as vm4.16b = [0x00030003, ...], (masking)
*   				vc0.4s = [c00, c01, c02, c03]
*					vc1.4s = [c10, c11, c12, c13]
*	Intermediate Values/Vectors:
*					v6 as vd 
**************************************************/
.macro mcbd3 a, c0, c1
	// f0 = a
	tbl		v\a\().16b, {v\a\().16b}, v0.16b	// f0 = shuffle(f0)

	ushr 	v6.4s, v\a\().4s, 1					// f1 = f0 >> 1
	ushr 	v\c0\().4s, v\a\().4s, 2			// f2 = f0 >> 2
	and		v\a\().16b, v\a\().16b, v1.16b		// f0 = f0 & mask249
	and		v6.16b, v6.16b, v1.16b				// f1 = f1 & mask249
	and		v\c0\().16b, v\c0\().16b, v1.16b	// f2 = f2 & mask249
	add		v\a\().4s, v\a\().4s, v6.4s			// f0 = f0 + f1
	add		v\a\().4s, v\a\().4s, v\c0\().4s	// f0 = f0 + f2

	ushr 	v6.4s, v\a\().4s, 3					// f1 = f0 >> 3
	add		v\a\().4s, v\a\().4s, v2.4s			// f0 = f0 + mask6db
	sub		v\a\().4s, v\a\().4s, v6.4s			// f0 = f0 - f1

	shl		v6.4s, v\a\().4s, #10				// f1 = f0 << 10
	ushr	v\c0\().4s, v\a\().4s, #12			// f2 = f0 >> 12
	ushr	v\c1\().4s, v\a\().4s, #2			// f3 = f0 >> 2
	and		v\a\().16b, v\a\().16b, v3.16b		// f0 = f0 & mask7
	and		v6.16b, v6.16b, v4.16b				// f1 = f1 & mask70
	and		v\c0\().16b, v\c0\().16b, v3.16b	// f2 = f2 & mask7
	and		v\c1\().16b, v\c1\().16b, v4.16b	// f3 = f3 & mask70
	add		v\a\().8h, v\a\().8h, v6.8h			// f0 = f0 + f1
	add		v6.8h, v\c0\().8h, v\c1\().8h		// f1 = f2 + f3
	sub		v\a\().8h, v\a\().8h, v5.8h			// f0 = f0 - mask3
	sub		v6.8h, v6.8h, v5.8h					// f1 = f1 - mask3

	zip1	v\c0\().4s, v\a\().4s, v6.4s
	zip2	v\c1\().4s, v\a\().4s, v6.4s
.endm



/*************************************************
*	Function Name:	kyber_cbd3_armv8
*	Description:	Given an array of uniformly random bytes, compute
*					polynomial with coefficients distributed according to
*					a centered binomial distribution with parameter eta=3
*	Corresponds to:	void kyber_cbd3_armv8(poly *r, const uint8_t *buf);
*	Arguments:		x0 as poly *r
*					x1 as const uint8_t *buf
*					x2 as masking values
*	Notes:			- Shuffling/Masking values are loaded to the vectors v0-v5
*					- (1st/2nd Half of) Buf values are loaded to the vectors v8-v15
*					- (1st/2nd Half of) R values are stored from the vectors v16-v31
*					- The vector v6 is registered for the intermediate values in the macro "mcbd3"
*					- The function is completed in two parts (because of the limited number of vectors)
**************************************************/	
.cbd3Consts:
.word	0xFF020100		// shuffle (-1, 2, 1, 0)
.word 	0xFF050403		// shuffle (-1, 5, 4, 3)
.word	0xFF080706		// shuffle (-1, 8, 7, 6)
.word	0xFF0B0A09		// shuffle (-1, 11, 10, 9)
.word	0x00249249		// mask 249
.word	0x006DB6DB		// mask 6DB
.word	0x00000007		// mask 7
.word	0x00070000		// mask 70
.word	0x00030003		// mask 3

SYM_FUNC_START(kyber_cbd3_armv8)
SYM_FUNC_ENTER(kyber_cbd3_armv8)
.align	4

	// Load the masking values
	adr   	x2, .cbd3Consts
	ld1		{v0.4s}, [x2], #16		// shuffle vector
	ld1r	{v1.4s}, [x2], #4		// mask249
	ld1r	{v2.4s}, [x2], #4		// mask6db
	ld1r	{v3.4s}, [x2], #4		// mask7
	ld1r	{v4.4s}, [x2], #4		// mask70
	ld1r	{v5.4s}, [x2], #4		// mask3

	// Load buf values, CBD2 Computations, store r values (part 1)
	ld1   	{v8.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v9.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v10.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v11.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v12.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v13.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v14.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v15.16b}, [x1]
	add		x1, x1, #12	
	
	mcbd3	8, 16, 17
	mcbd3	9, 18, 19
	mcbd3	10, 20, 21
	mcbd3	11, 22, 23

	mcbd3	12, 24, 25
	mcbd3	13, 26, 27
	mcbd3	14, 28, 29
	mcbd3	15, 30, 31

	st1		{v16.4s-v19.4s}, [x0], #64
	st1		{v20.4s-v23.4s}, [x0], #64
	st1		{v24.4s-v27.4s}, [x0], #64
	st1		{v28.4s-v31.4s}, [x0], #64

	// Load buf values, CBD2 Computations, store r values (part 2)
	ld1   	{v8.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v9.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v10.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v11.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v12.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v13.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v14.16b}, [x1]
	add		x1, x1, #12
	ld1   	{v15.16b}, [x1]
	add		x1, x1, #12	
	
	mcbd3	8, 16, 17
	mcbd3	9, 18, 19
	mcbd3	10, 20, 21
	mcbd3	11, 22, 23

	mcbd3	12, 24, 25
	mcbd3	13, 26, 27
	mcbd3	14, 28, 29
	mcbd3	15, 30, 31

	st1		{v16.4s-v19.4s}, [x0], #64
	st1		{v20.4s-v23.4s}, [x0], #64
	st1		{v24.4s-v27.4s}, [x0], #64
	st1		{v28.4s-v31.4s}, [x0], #64

	//
	RET
SYM_FUNC_END(kyber_cbd3_armv8)

ASM_END
