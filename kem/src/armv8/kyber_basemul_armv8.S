/* ARMv8 implementation of BASEMUL function */
/* Called in POLY.C (See void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)) */
/* New version (v2) */

#include "assembler_support.h"
#include "kyber_type.h"

.include "macros.inc"

/*************************************************
*	Macro Name:		basemul
*	Description:	(Core part)
*					Multiplication of polynomials in Zq[X]/(X^2-zeta)
*					i.e. (c0 + c1 X)  = (a0 + a1 X)*(b0 * b1 X) mod (X^2-zeta)
*	Arguments:		(Core part)
*					va0.8h = [a00, a01, ..., a07],
*					va1.8h = [a10, a11, ..., a17],
*					vb0.8h = [b00, b01, ..., b07],
*					vb1.8h = [b10, b11, ..., b17],
*					vz.8h = [z0, −z0, ..., z3, −z3],
*					vc0.8h = [c00, c01, ..., c07],
*					vc1.8h = [c10, c11, ..., c17]
*	Intermediate Values/Vectors: v0, v9, v10, v11, v16, v17, v18, v19, v20, v21, v22
*	Notes:			- It requires pre- and post- operations to re-order
*					because the polynomial in NTT domain is originally ordered as
*					a0, a1 -> a0 + a1 * X
*					- It requires to construct vz vector from zetas
**************************************************/
.macro basemul C0, C1, A0, A1, B0, B1
	// Construct vz
	ld1		{v8.4h}, [x3], #8					// read 4 element from zeta vector
	zip1	v8.8h, v8.8h, v8.8h
	neg		v9.8h, v8.8h
	trn1	v8.8h, v8.8h, v9.8h 				// v0 = vz = [-zeta4, zeta4, -zeta3, zeta3, -zeta2, zeta2, -zeta, zeta]

	// Core part of basemul
	fqmul	\C0, \A1, \B1  						// a1 * b1
	fqmul	\C0, \C0, 8							// a1 * b1 * zeta
	fqmul	8, \A0, \B0  						// a0 * b0
	add		v\C0\().8h, v\C0\().8h, v8.8h  		// c0
	fqmul	\C1\(), \A0, \B1  					// a0 * b1
	fqmul	8, \A1, \B0  						// a1 * b0
	add		v\C1\().8h, v\C1\().8h, v8.8h  		// c1
.endm


// One iteration
.macro basemul4
	// Load A vectors
	ld2   {v16.8h, v17.8h}, [x1], #32
	ld2   {v18.8h, v19.8h}, [x1], #32
	ld2   {v20.8h, v21.8h}, [x1], #32
	ld2   {v22.8h, v23.8h}, [x1], #32
	// Load B vectors
	ld2   {v24.8h, v25.8h}, [x2], #32
	ld2   {v26.8h, v27.8h}, [x2], #32
	ld2   {v28.8h, v29.8h}, [x2], #32
	ld2   {v30.8h, v31.8h}, [x2], #32

	basemul 0, 1, 16, 17, 24, 25
	basemul 2, 3, 18, 19, 26, 27
	basemul 4, 5, 20, 21, 28, 29
	basemul 6, 7, 22, 23, 30, 31

	// Store C vectors
	st2   {v0.8h, v1.8h}, [x0], #32
	st2   {v2.8h, v3.8h}, [x0], #32
	st2   {v4.8h, v5.8h}, [x0], #32
	st2   {v6.8h, v7.8h}, [x0], #32
.endm

/*************************************************
*	Function Name:	kyber_basemul_armv8
*	Description:	Pointwise multiplication of polynomials
*	Corresponds to:	void kyber_basemul_armv8(int16_t *poly, const int16_t *a, const int16_t *b, const int16_t* zetas);
*	Arguments:		x0 as int16_t *poly
*					x1 as const int16_t *a
*					x2 as const int16_t *b
*					x3 as const int16_t* zetas
*	Notes:			- q = 3329 and qinv = 62209 are stored in the vector v15
*					- The address of the second block of zetas is used.
*					- There are 32 vectors for 256 * 16bits for each A and B. They are loaded as 4 vectors in 8 iterations.
*					  The result vector C is also stored as 4 vectors in each iteration.
*					- basemul macro is called twice in each iteration.
**************************************************/
SYM_FUNC_START(kyber_basemul_armv8)
SYM_FUNC_ENTER(kyber_basemul_armv8)
.align	4
	mov w4, 3329
  	mov v15.h[0], w4				// v15.s[0] = q = 3329 = 0D01
  	mov w4, 62209
	mov v15.h[1], w4				// v15.s[1] = qinv = 62209
	add   x3, x3, #128				// The address of second block of zetas: (+ 64 * 2byte)

	basemul4
	basemul4
	basemul4
	basemul4

	RET
SYM_FUNC_END(kyber_basemul_armv8)
