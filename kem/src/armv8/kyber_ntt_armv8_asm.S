/* ARMv8 implementation of NTT-functions */
/* Called in NTT.H */
/* New version (v2) */

// Requires fqmul, shuffle4, shuffle2
.include "macros.inc"

/*************************************************
*	Macro Name:		butterfly
*	Description:	ButterFly operation in NTT
*					i.e. (a, b) <- (a + b*z, a - b*z)
*	Arguments:		a as va.8h = [a0, a1, ..., a7],
*					b as vb.8h = [b0, b1, ..., b7],
*					zetas as vz.8h = [z0, z1, ..., z7]
*	Intermediate Values/Vectors:
*					v14 as vc
**************************************************/
.macro butterfly a, b, zetas
	fqmul	14, \zetas, \b
	sub		v\b\().8h, v\a\().8h, v14.8h
	add		v\a\().8h, v\a\().8h, v14.8h
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

	st1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r96
	st1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r128
	add 	x0, x0, #128				// after: x0 at r192
	st1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r224
	st1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r256
	sub		x0, x0, #512				// after: x0 at r0
.endm

.macro levels6to1
	/* Load the half */
	ld1   {v16.8h-v19.8h}, [x0], #64	// after: x0 at r32
	ld1   {v20.8h-v23.8h}, [x0], #64	// after: x0 at r64
	ld1   {v24.8h-v27.8h}, [x0], #64	// after: x0 at r96
	ld1   {v28.8h-v31.8h}, [x0], #64	// after: x0 at r128
	sub		x0, x0, #256				// after: x0 at r0

	/* Level 6 */
	ld1r	{v0.8h}, [x1], #2			// Zeta vector z2:...:z2

	butterfly 16, 24, 0
	butterfly 17, 25, 0
	butterfly 18, 26, 0
	butterfly 19, 27, 0
	butterfly 20, 28, 0
	butterfly 21, 29, 0
	butterfly 22, 30, 0
	butterfly 23, 31, 0

	/* Level 5 */
	ld2r	{v0.8h, v1.8h}, [x1], #4	// Zeta vectors [z4] and [z5]

	butterfly 16, 20, 0
	butterfly 17, 21, 0
	butterfly 18, 22, 0
	butterfly 19, 23, 0
	butterfly 24, 28, 1
	butterfly 25, 29, 1
	butterfly 26, 30, 1
	butterfly 27, 31, 1

	/* Level 4 */
	ld4r	{v0.8h, v1.8h, v2.8h, v3.8h}, [x1], #8			// Zeta vectors [z8], [z9], [z10], [z11]

	butterfly 16, 18, 0
	butterfly 17, 19, 0
	butterfly 20, 22, 1
	butterfly 21, 23, 1
	butterfly 24, 26, 2
	butterfly 25, 27, 2
	butterfly 28, 30, 3
	butterfly 29, 31, 3

	/* Level 3 */
	ld4r	{v0.8h, v1.8h, v2.8h, v3.8h}, [x1], #8			// Zeta vectors [z16], [z17], [z18], [z19]
	ld4r	{v4.8h, v5.8h, v6.8h, v7.8h}, [x1], #8			// Zeta vectors [z20], [z21], [z22], [z23]

	butterfly 16, 17, 0
	butterfly 18, 19, 1
	butterfly 20, 21, 2
	butterfly 22, 23, 3
	butterfly 24, 25, 4
	butterfly 26, 27, 5
	butterfly 28, 29, 6
	butterfly 30, 31, 7

	/* Level 2 */
	shuffle4 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	// Zeta vectors
	// v0: 	z32	z32 z32	z32	z33	z33	z33	z33
	// v1:	z34	z34	z34	z34	z35	z35	z35	z35
	// v2:	z36	z36	z36	z36	z37	z37	z37	z37
	// v3: 	z38	z38	z38	z38	z39	z39	z39	z39
	// v4: 	z40	z40	z40	z40	z41	z41	z41	z41
	// v5: 	z42	z42	z42	z42	z43	z43	z43	z43
	// v6:	z44	z44	z44	z44	z45	z45	z45	z45
	// v7:	z46	z46	z46	z46	z47	z47	z47	z47
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

	/* Level 1 */
	shuffle2 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29 

	// Zeta vectors
	// v0:	z64	z64	z65	z65	z66	z66	z67	z67
	// v1:	z68	z68	z69	z69	z70	z70	z71	z71
	// v2:	z72	z72	z73	z73	z74	z74	z75	z75
	// v3:	z76	z76	z77	z77	z78	z78	z79	z79
	// v4:	z80	z80	z81	z81	z82	z82	z83	z83
	// v5:	z84	z84	z85	z85	z86	z86	z87	z87
	// v6:	z88	z88	z89	z89	z90	z90	z91	z91
	// v7:	z92	z92	z93	z93	z94	z94	z95	z95
	ld1		{v0.8h-v3.8h}, [x1], #64	
	ld1		{v4.8h-v7.8h}, [x1], #64	

	butterfly 28, 29, 0
	butterfly 30, 31, 1
	butterfly 16, 17, 2
	butterfly 18, 19, 3
	butterfly 20, 21, 4
	butterfly 22, 23, 5
	butterfly 24, 25, 6
	butterfly 26, 27, 7

	st2   {v28.4s, v29.4s}, [x0], #32	// after: x0 at r16
	st2   {v30.4s, v31.4s}, [x0], #32	// after: x0 at r32
	st2   {v16.4s, v17.4s}, [x0], #32	// after: x0 at r48
	st2   {v18.4s, v19.4s}, [x0], #32	// after: x0 at r64
	st2   {v20.4s, v21.4s}, [x0], #32	// after: x0 at r80
	st2   {v22.4s, v23.4s}, [x0], #32	// after: x0 at r96
	st2   {v24.4s, v25.4s}, [x0], #32	// after: x0 at r112
	st2   {v26.4s, v27.4s}, [x0], #32	// after: x0 at r128
.endm


/*************************************************
*	Function Name:	kyber_ntt_armv8
*	Description:	Inplace number-theoretic transform (NTT) in Rq.
*					input is in standard order, output is in bitreversed order
*	Corresponds to:	void kyber_ntt_armv8(int16_t *r, const int16_t* zetas);
*	Arguments:		x0 as int16_t *r
*					x1 as const int16_t* zetas
*	Notes:			- It is implemented in 7 levels: From Level 7 to Level 1
*					- q = 3329 and qinv = 62209 are stored in the vector v15
*					- It uses x3 and x4 as counters
**************************************************/
.global kyber_ntt_armv8
kyber_ntt_armv8:
	// pre-operations
	mov		w4, 3329
  	mov		v15.h[0], w4		// v15.s[0] = q = 3329 = 0D01
  	mov		w4, 62209
    mov		v15.h[1], w4 		// v15.s[1] = qinv = 62209

    level7
    levels6to1
    levels6to1

	ret
