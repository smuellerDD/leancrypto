/* ARMv8 implementation of ADD function */

#include "assembler_support.h"
#include "kyber_type.h"

/*************************************************
*	Function Name:	kyber_add_armv8
*
*	Called in:		void poly_add(poly *r, const poly *a, const poly *b)
*	Description:	r <- a + b
**************************************************/
SYM_FUNC_START(kyber_add_armv8)
SYM_FUNC_ENTER(kyber_add_armv8)
.align	4
	ld4   {v0.8h-v3.8h}, [x1], #64
	ld4   {v4.8h-v7.8h}, [x1], #64
	ld4   {v8.8h-v11.8h}, [x1], #64
	ld4   {v12.8h-v15.8h}, [x1], #64
	
	ld4   {v16.8h-v19.8h}, [x2], #64
	ld4   {v20.8h-v23.8h}, [x2], #64
	ld4   {v24.8h-v27.8h}, [x2], #64
	ld4   {v28.8h-v31.8h}, [x2], #64
	
	add   v16.8h, v0.8h, v16.8h
	add   v17.8h, v1.8h, v17.8h
	add   v18.8h, v2.8h, v18.8h
	add   v19.8h, v3.8h, v19.8h
	add   v20.8h, v4.8h, v20.8h
	add   v21.8h, v5.8h, v21.8h
	add   v22.8h, v6.8h, v22.8h
	add   v23.8h, v7.8h, v23.8h
	add   v24.8h, v8.8h, v24.8h
	add   v25.8h, v9.8h, v25.8h
	add   v26.8h, v10.8h, v26.8h
	add   v27.8h, v11.8h, v27.8h
	add   v28.8h, v12.8h, v28.8h
	add   v29.8h, v13.8h, v29.8h
	add   v30.8h, v14.8h, v30.8h
	add   v31.8h, v15.8h, v31.8h
	
	st4   {v16.8h-v19.8h}, [x0], #64
	st4   {v20.8h-v23.8h}, [x0], #64
	st4   {v24.8h-v27.8h}, [x0], #64
	st4   {v28.8h-v31.8h}, [x0], #64
	
	ld4   {v0.8h-v3.8h}, [x1], #64
	ld4   {v4.8h-v7.8h}, [x1], #64
	ld4   {v8.8h-v11.8h}, [x1], #64
	ld4   {v12.8h-v15.8h}, [x1]
	
	ld4   {v16.8h-v19.8h}, [x2], #64
	ld4   {v20.8h-v23.8h}, [x2], #64
	ld4   {v24.8h-v27.8h}, [x2], #64
	ld4   {v28.8h-v31.8h}, [x2]
	
	add   v16.8h, v0.8h, v16.8h
	add   v17.8h, v1.8h, v17.8h
	add   v18.8h, v2.8h, v18.8h
	add   v19.8h, v3.8h, v19.8h
	add   v20.8h, v4.8h, v20.8h
	add   v21.8h, v5.8h, v21.8h
	add   v22.8h, v6.8h, v22.8h
	add   v23.8h, v7.8h, v23.8h
	add   v24.8h, v8.8h, v24.8h
	add   v25.8h, v9.8h, v25.8h
	add   v26.8h, v10.8h, v26.8h
	add   v27.8h, v11.8h, v27.8h
	add   v28.8h, v12.8h, v28.8h
	add   v29.8h, v13.8h, v29.8h
	add   v30.8h, v14.8h, v30.8h
	add   v31.8h, v15.8h, v31.8h
	
	st4   {v16.8h-v19.8h}, [x0], #64
	st4   {v20.8h-v23.8h}, [x0], #64
	st4   {v24.8h-v27.8h}, [x0], #64
	st4   {v28.8h-v31.8h}, [x0]
	
	RET
SYM_FUNC_END(kyber_add_armv8)


LC_ASM_END
