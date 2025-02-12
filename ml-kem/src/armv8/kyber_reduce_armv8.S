/* ARMv8 implementation of Reductions */
/* Called in REDUCE.H */ 

#include "assembler_support.h"
#include "kyber_type.h"

// Include macros mbarret16
.include "macros.inc"

/*************************************************
*	Function Name:	kyber_barret_red_armv8
*	Description:	Barrett reduction
*	Corresponds to:	void kyber_barret_red_armv8(int16_t* a);
*	Arguments:		x0 as int16_t *a
*	Notes:			- 
**************************************************/
SYM_FUNC_START(kyber_barret_red_armv8)
SYM_FUNC_ENTER(kyber_barret_red_armv8)
.align	4
	// load a
	ld1   {v16.8h-v19.8h}, [x0], #64
	ld1   {v20.8h-v23.8h}, [x0], #64
	ld1   {v24.8h-v27.8h}, [x0], #64
	ld1   {v28.8h-v31.8h}, [x0], #64

	// Barrett Reduction
	mbarret16 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	// Store
	sub   x0, x0, #256
	st1   {v16.8h-v19.8h}, [x0], #64
	st1   {v20.8h-v23.8h}, [x0], #64
	st1   {v24.8h-v27.8h}, [x0], #64
	st1   {v28.8h-v31.8h}, [x0], #64

	RET
SYM_FUNC_END(kyber_barret_red_armv8)
	
	
/*************************************************
*	Function Name:	kyber_tomont_armv8
*	Description:	Montgomery reduction
*	Corresponds to:	void kyber_tomont_armv8(int16_t* a);
*	Arguments:		x0 as int16_t *a
*	Notes:			- 
**************************************************/
SYM_FUNC_START(kyber_tomont_armv8)
SYM_FUNC_ENTER(kyber_tomont_armv8)
.align	4

	// load a
	ld1   {v16.4s-v19.4s}, [x0], #64
	ld1   {v20.4s-v23.4s}, [x0], #64
	ld1   {v24.4s-v27.4s}, [x0], #64
	ld1   {v28.4s-v31.4s}, [x0], #64	

	// load constants
	mov w4, 3329
	mov v15.h[0], w4		// v15.s[0] = q = 3329 = 0D01
	mov w4, 62209
	mov v15.h[1], w4 		// v15.s[1] = qinv = 62209
	mov w4, 1353
	mov v15.h[2], w4 		// v15.s[2] = f = 1353 used in Montgomerys reduction

	// Montgomery 
	mtomont 16
	mtomont 17
	mtomont 18
	mtomont 19
	mtomont 20
	mtomont 21
	mtomont 22
	mtomont 23
	mtomont 24
	mtomont 25
	mtomont 26
	mtomont 27
	mtomont 28
	mtomont 29
	mtomont 30
	mtomont 31

	// Store
	sub   x0, x0, #256	
	st1   {v16.8h-v19.8h}, [x0], #64
	st1   {v20.8h-v23.8h}, [x0], #64
	st1   {v24.8h-v27.8h}, [x0], #64
	st1   {v28.8h-v31.8h}, [x0], #64

    	RET
SYM_FUNC_END(kyber_tomont_armv8)
	
	
// void kyber_sub_reduce_armv8(poly *r, const poly *a, const poly *b)
// r = reduce(a-b)
SYM_FUNC_START(kyber_sub_reduce_armv8)
SYM_FUNC_ENTER(kyber_sub_reduce_armv8)
.align	4

	// load a
	ld1   {v16.8h-v19.8h}, [x1], #64
	ld1   {v20.8h-v23.8h}, [x1], #64
	ld1   {v24.8h-v27.8h}, [x1], #64
	ld1   {v28.8h-v31.8h}, [x1], #64

	// load b
	ld1   {v0.8h-v3.8h}, [x2], #64
	ld1   {v4.8h-v7.8h}, [x2], #64
	ld1   {v8.8h-v11.8h}, [x2], #64
	ld1   {v12.8h-v15.8h}, [x2], #64

	// r <- a - b
	sub   v16.8h, v16.8h, v0.8h
	sub   v17.8h, v17.8h, v1.8h
	sub   v18.8h, v18.8h, v2.8h
	sub   v19.8h, v19.8h, v3.8h
	sub   v20.8h, v20.8h, v4.8h
	sub   v21.8h, v21.8h, v5.8h
	sub   v22.8h, v22.8h, v6.8h
	sub   v23.8h, v23.8h, v7.8h
	sub   v24.8h, v24.8h, v8.8h
	sub   v25.8h, v25.8h, v9.8h
	sub   v26.8h, v26.8h, v10.8h
	sub   v27.8h, v27.8h, v11.8h
	sub   v28.8h, v28.8h, v12.8h
	sub   v29.8h, v29.8h, v13.8h
	sub   v30.8h, v30.8h, v14.8h
	sub   v31.8h, v31.8h, v15.8h

	// Barrett Reduction on r
	mbarret16 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	// Store
	st1   {v16.8h-v19.8h}, [x0], #64
	st1   {v20.8h-v23.8h}, [x0], #64
	st1   {v24.8h-v27.8h}, [x0], #64
	st1   {v28.8h-v31.8h}, [x0], #64
	
	RET
SYM_FUNC_END(kyber_sub_reduce_armv8)
	

// void kyber_add_reduce_armv8(poly *r, const poly *a, const poly *b)
// r = reduce(a+b)
SYM_FUNC_START(kyber_add_reduce_armv8)
SYM_FUNC_ENTER(kyber_add_reduce_armv8)
.align	4

	// load a
	ld1   {v16.8h-v19.8h}, [x1], #64
	ld1   {v20.8h-v23.8h}, [x1], #64
	ld1   {v24.8h-v27.8h}, [x1], #64
	ld1   {v28.8h-v31.8h}, [x1], #64

	// load b
	ld1   {v0.8h-v3.8h}, [x2], #64
	ld1   {v4.8h-v7.8h}, [x2], #64
	ld1   {v8.8h-v11.8h}, [x2], #64
	ld1   {v12.8h-v15.8h}, [x2], #64

		// r <- a + b
	add   v16.8h, v16.8h, v0.8h
	add   v17.8h, v17.8h, v1.8h
	add   v18.8h, v18.8h, v2.8h
	add   v19.8h, v19.8h, v3.8h
	add   v20.8h, v20.8h, v4.8h
	add   v21.8h, v21.8h, v5.8h
	add   v22.8h, v22.8h, v6.8h
	add   v23.8h, v23.8h, v7.8h
	add   v24.8h, v24.8h, v8.8h
	add   v25.8h, v25.8h, v9.8h
	add   v26.8h, v26.8h, v10.8h
	add   v27.8h, v27.8h, v11.8h
	add   v28.8h, v28.8h, v12.8h
	add   v29.8h, v29.8h, v13.8h
	add   v30.8h, v30.8h, v14.8h
	add   v31.8h, v31.8h, v15.8h

	// Barrett Reduction on r
	mbarret16 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	// Store
	st1   {v16.8h-v19.8h}, [x0], #64
	st1   {v20.8h-v23.8h}, [x0], #64
	st1   {v24.8h-v27.8h}, [x0], #64
	st1   {v28.8h-v31.8h}, [x0], #64
	
	RET
SYM_FUNC_END(kyber_add_reduce_armv8)
	
	
// void kyber_add_add_reduce_armv8(poly *r, const poly *a, const poly *b,
//				   const poly *c)
// r = reduce(a+b+c)
SYM_FUNC_START(kyber_add_add_reduce_armv8)
SYM_FUNC_ENTER(kyber_add_add_reduce_armv8)
.align	4

	// load a
	ld1   {v16.8h-v19.8h}, [x1], #64
	ld1   {v20.8h-v23.8h}, [x1], #64
	ld1   {v24.8h-v27.8h}, [x1], #64
	ld1   {v28.8h-v31.8h}, [x1], #64

	// load b
	ld1   {v0.8h-v3.8h}, [x2], #64
	ld1   {v4.8h-v7.8h}, [x2], #64
	ld1   {v8.8h-v11.8h}, [x2], #64
	ld1   {v12.8h-v15.8h}, [x2], #64

		// r <- a + b
	add   v16.8h, v16.8h, v0.8h
	add   v17.8h, v17.8h, v1.8h
	add   v18.8h, v18.8h, v2.8h
	add   v19.8h, v19.8h, v3.8h
	add   v20.8h, v20.8h, v4.8h
	add   v21.8h, v21.8h, v5.8h
	add   v22.8h, v22.8h, v6.8h
	add   v23.8h, v23.8h, v7.8h
	add   v24.8h, v24.8h, v8.8h
	add   v25.8h, v25.8h, v9.8h
	add   v26.8h, v26.8h, v10.8h
	add   v27.8h, v27.8h, v11.8h
	add   v28.8h, v28.8h, v12.8h
	add   v29.8h, v29.8h, v13.8h
	add   v30.8h, v30.8h, v14.8h
	add   v31.8h, v31.8h, v15.8h

	// load c
	ld1   {v0.8h-v3.8h}, [x3], #64
	ld1   {v4.8h-v7.8h}, [x3], #64
	ld1   {v8.8h-v11.8h}, [x3], #64
	ld1   {v12.8h-v15.8h}, [x3], #64

		// r <- r + c
	add   v16.8h, v16.8h, v0.8h
	add   v17.8h, v17.8h, v1.8h
	add   v18.8h, v18.8h, v2.8h
	add   v19.8h, v19.8h, v3.8h
	add   v20.8h, v20.8h, v4.8h
	add   v21.8h, v21.8h, v5.8h
	add   v22.8h, v22.8h, v6.8h
	add   v23.8h, v23.8h, v7.8h
	add   v24.8h, v24.8h, v8.8h
	add   v25.8h, v25.8h, v9.8h
	add   v26.8h, v26.8h, v10.8h
	add   v27.8h, v27.8h, v11.8h
	add   v28.8h, v28.8h, v12.8h
	add   v29.8h, v29.8h, v13.8h
	add   v30.8h, v30.8h, v14.8h
	add   v31.8h, v31.8h, v15.8h

	// Barrett Reduction on r
	mbarret16 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31

	// Store
	st1   {v16.8h-v19.8h}, [x0], #64
	st1   {v20.8h-v23.8h}, [x0], #64
	st1   {v24.8h-v27.8h}, [x0], #64
	st1   {v28.8h-v31.8h}, [x0], #64
	
	RET
SYM_FUNC_END(kyber_add_add_reduce_armv8)

ASM_END
