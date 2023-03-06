/* ARMv8 implementation of InvNTT-functions */
/* Called in NTT.H */
/* v2 */

#include "assembler_support.h"

// Requires fqmul, shuffle4, shuffle2
.include "macros.inc"

/*************************************************
*	Macro Name:		butterfly
*	Description:	ButterFly operation in inverse NTT
**************************************************/
.macro butterfly a, b, zetas
	mov		v14.16b, v\a\().16b					// vc <- va
	add		v\a\().8h, v14.8h, v\b\().8h		// va = vb + vc
	mbarret	\a									// va = BarretRed(va)
	sub		v\b\().8h, v\b\().8h, v14.8h 		// vb = vb - vc
	fqmul 	\b, \zetas, \b						// vb = vb * zetas
.endm

.macro levels1to6
	/* Level 1 */
	ld2   {v16.4s, v17.4s}, [x0], #32	// after: x0 at r16
	ld2   {v18.4s, v19.4s}, [x0], #32	// after: x0 at r32
	ld2   {v20.4s, v21.4s}, [x0], #32	// after: x0 at r48
	ld2   {v22.4s, v23.4s}, [x0], #32	// after: x0 at r64
	ld2   {v24.4s, v25.4s}, [x0], #32	// after: x0 at r80
	ld2   {v26.4s, v27.4s}, [x0], #32	// after: x0 at r96
	ld2   {v28.4s, v29.4s}, [x0], #32	// after: x0 at r112
	ld2   {v30.4s, v31.4s}, [x0], #32	// after: x0 at r128
	sub		x0, x0, #256				// after: x0 at r0

	// Load zetas
	ld1		{v0.8h-v3.8h}, [x1], #64
	ld1		{v4.8h-v7.8h}, [x1], #64

	// butterfly
	butterfly 16, 17, 0
	butterfly 18, 19, 1
	butterfly 20, 21, 2
	butterfly 22, 23, 3
	butterfly 24, 25, 4
	butterfly 26, 27, 5
	butterfly 28, 29, 6
	butterfly 30, 31, 7

	/* Level 2 */
	shuffle2 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	ld1		{v0.8h-v3.8h}, [x1], #64
	ld1		{v4.8h-v7.8h}, [x1], #64

	butterfly 30, 31, 0
	butterfly 16, 17, 1
	butterfly 18, 19, 2
	butterfly 20, 21, 3
	butterfly 22, 23, 4
	butterfly 24, 25, 5
	butterfly 26, 27, 6
	butterfly 28, 29, 7

	/* Level 3 */
	shuffle4 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29 

	ld4r	{v0.8h, v1.8h, v2.8h, v3.8h}, [x1], #8			// Zeta vectors [z16], [z17], [z18], [z19]
	ld4r	{v4.8h, v5.8h, v6.8h, v7.8h}, [x1], #8			// Zeta vectors [z20], [z21], [z22], [z23]

	butterfly 28, 29, 0
	butterfly 30, 31, 1
	butterfly 16, 17, 2
	butterfly 18, 19, 3
	butterfly 20, 21, 4
	butterfly 22, 23, 5
	butterfly 24, 25, 6
	butterfly 26, 27, 7

	/* Level 4 */
	ld4r	{v0.8h, v1.8h, v2.8h, v3.8h}, [x1], #8			// Zeta vectors [z8], [z9], [z10], [z11]

	butterfly 28, 30, 0
	butterfly 29, 31, 0
	butterfly 16, 18, 1
	butterfly 17, 19, 1
	butterfly 20, 22, 2
	butterfly 21, 23, 2
	butterfly 24, 26, 3
	butterfly 25, 27, 3

	/* Level 5 */
	ld2r	{v0.8h, v1.8h}, [x1], #4	// Zeta vectors [z4] and [z5]

	butterfly 28, 16, 0
	butterfly 29, 17, 0
	butterfly 30, 18, 0
	butterfly 31, 19, 0
	butterfly 20, 24, 1
	butterfly 21, 25, 1
	butterfly 22, 26, 1
	butterfly 23, 27, 1

	/* Level 6 */
	ld1r	{v0.8h}, [x1], #2			// Zeta vector z2:...:z2

	butterfly 28, 20, 0
	butterfly 29, 21, 0
	butterfly 30, 22, 0
	butterfly 31, 23, 0
	butterfly 16, 24, 0
	butterfly 17, 25, 0
	butterfly 18, 26, 0
	butterfly 19, 27, 0

	/* Store */
	st1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r32
	st1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r64
	st1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r96
	st1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r128
.endm

.macro level7
	ld1r	{v0.8h}, [x1], #2			// Zeta vector z1:...:z1

	// x0 at r0
	ld1	  {v16.8h-v19.8h}, [x0], #64	// after: x0 at r32
	ld1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r64
	add		x0, x0, #128				// after: x0 at r128
	ld1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r160
	ld1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r192
	sub		x0, x0, #384				// after: x0 at r0

	butterfly 16, 24, 0
	butterfly 17, 25, 0
	butterfly 18, 26, 0
	butterfly 19, 27, 0
	butterfly 20, 28, 0
	butterfly 21, 29, 0
	butterfly 22, 30, 0
	butterfly 23, 31, 0


	mov		w5, 1441		// MONT^2 / 128
	dup 	v1.8h, w5
	fqmul 16, 16, 1
	fqmul 17, 17, 1
	fqmul 18, 18, 1
	fqmul 19, 19, 1
	fqmul 20, 20, 1
	fqmul 21, 21, 1
	fqmul 22, 22, 1
	fqmul 23, 23, 1
	fqmul 24, 24, 1
	fqmul 25, 25, 1
	fqmul 26, 26, 1
	fqmul 27, 27, 1
	fqmul 28, 28, 1
	fqmul 29, 29, 1
	fqmul 30, 30, 1
	fqmul 31, 31, 1


	st1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r32
	st1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r64
	add 	x0, x0, #128				// after: x0 at r128
	st1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r160
	st1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r192
	sub		x0, x0, #256				// after: x0 at r64

	ld1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r96
	ld1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r128
	add 	x0, x0, #128				// after: x0 at r192
	ld1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r224
	ld1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r256
	sub		x0, x0, #384				// after: x0 at r64

	butterfly 16, 24, 0
	butterfly 17, 25, 0
	butterfly 18, 26, 0
	butterfly 19, 27, 0
	butterfly 20, 28, 0
	butterfly 21, 29, 0
	butterfly 22, 30, 0
	butterfly 23, 31, 0


	fqmul 16, 16, 1
	fqmul 17, 17, 1
	fqmul 18, 18, 1
	fqmul 19, 19, 1
	fqmul 20, 20, 1
	fqmul 21, 21, 1
	fqmul 22, 22, 1
	fqmul 23, 23, 1
	fqmul 24, 24, 1
	fqmul 25, 25, 1
	fqmul 26, 26, 1
	fqmul 27, 27, 1
	fqmul 28, 28, 1
	fqmul 29, 29, 1
	fqmul 30, 30, 1
	fqmul 31, 31, 1

	st1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r96
	st1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r128
	add 	x0, x0, #128				// after: x0 at r192
	st1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r224
	st1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r256
.endm



/*************************************************
*	Function Name:	kyber_inv_ntt_armv8
*	Description:	Inplace inverse number-theoretic transform in Rq and
*              		multiplication by Montgomery factor 2^16.
*              		Input is in bitreversed order, output is in standard order
*	Corresponds to:	void kyber_inv_ntt_armv8(int16_t *r, const int16_t* zetas_inv);
*	Arguments:		x0 as int16_t *r
*					x1 as const int16_t* zetas
*	Notes:			- It is implemented in 8 levels: From Level 1 to Level 7
*					- q = 3329 and qinv = 62209 are stored in the vector v15
**************************************************/
SYM_FUNC_START(kyber_inv_ntt_armv8)
SYM_FUNC_ENTER(kyber_inv_ntt_armv8)
.align	4
	// pre-operations
	mov		w4, 3329
  	mov		v15.h[0], w4		// v15.s[0] = q = 3329 = 0D01
  	mov		w4, 62209
	mov		v15.h[1], w4 		// v15.s[1] = qinv = 62209
	mov 	w4, 20159
	mov 	v15.h[2], w4 		// v15.s[2] = v = 20159 used in Barrets reduction

	levels1to6
	levels1to6
	sub		x0, x0, #512		// after: x0 at r0
	level7

	RET
SYM_FUNC_END(kyber_inv_ntt_armv8)
