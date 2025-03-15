/* ARMv8 implementation of Polynomial Functions */

#include "assembler_support.h"
#include "kyber_type.h"


// poly_tobytes
// read a, b, c, d -> write e, f, g
.macro mtobytes a, b, c, d, e, f, g
	ushr	v1.8h, v\a\().8h, #15
	ushr	v2.8h, v\b\().8h, #15
	ushr	v3.8h, v\c\().8h, #15
	ushr	v4.8h, v\d\().8h, #15

	mla		v\a\().8h, v1.8h, v0.8h
	mla		v\b\().8h, v2.8h, v0.8h
	mla		v\c\().8h, v3.8h, v0.8h
	mla		v\d\().8h, v4.8h, v0.8h 	

	shl		v1.8h, v\a\().8h, #8
	shl		v2.8h, v\c\().8h, #8
	uzp2	v\e\().16b, v1.16b, v2.16b		// a0

	ushr	v\a\().8h, v\a\().8h, #8
	ushr	v\c\().8h, v\c\().8h, #8
	shl		v\b\().8h, v\b\().8h, #4
	shl		v\d\().8h, v\d\().8h, #4

	orr		v\a\().16b, v\a\().16b, v\b\().16b
	orr		v\c\().16b, v\c\().16b, v\d\().16b

	uzp1	v\f\().16b, v\a\().16b, v\c\().16b	// a1
	uzp2	v\g\().16b, v\a\().16b, v\c\().16b	// a2
.endm

// poly_frombytes
// read 3 vectors a|b|c
.macro mfrombytes a, b, c, d, e, f, g
	zip1  v\d\().16b, v\a\().16b, v\b\().16b	// r[2i] = b|a
	zip2  v\f\().16b, v\a\().16b, v\b\().16b
	zip1  v\e\().16b, v\b\().16b, v\c\().16b	// r[2i+1] = c|b
	zip2  v\g\().16b, v\b\().16b, v\c\().16b
	ushr  v\e\().8h, v\e\().8h, #4		// r[2i+1]c|b >> 4
	ushr  v\g\().8h, v\g\().8h, #4

	and  v\d\().16b, v\d\().16b, v0.16b	// & FFF
	and  v\e\().16b, v\e\().16b, v0.16b
	and  v\f\().16b, v\f\().16b, v0.16b
	and  v\g\().16b, v\g\().16b, v0.16b

	//and  v\c\().16b, v\d\().16b, v0.16b		// & FFF
	//udiv v\d\().16b, v\c\().16b, #3329		// division by 3329
	//mls  v\d\().16b, v\d\().16b, #3329, v\c\().16b	// udiv and mls form modulo operation

	//and  v\c\().16b, v\e\().16b, v0.16b
	//udiv v\e\().16b, v\c\().16b, #3329
	//mls  v\e\().16b, v\e\().16b, #3329, v\c\().16b

	//and  v\c\().16b, v\f\().16b, v0.16b
	//udiv v\f\().16b, v\c\().16b, #3329
	//mls  v\f\().16b, v\f\().16b, #3329, v\c\().16b

	//and  v\c\().16b, v\g\().16b, v0.16b
	//udiv v\g\().16b, v\c\().16b, #3329
	//mls  v\g\().16b, v\g\().16b, #3329, v\c\().16b
.endm

SYM_FUNC_START(kyber_poly_tobytes_armv8)
SYM_FUNC_ENTER(kyber_poly_tobytes_armv8)
.align	4
	mov w4, #3329
	mov v0.h[0], w4
	dup v0.8h, v0.h[0]

	ld2 	{v16.8h, v17.8h}, [x1], #32
	ld2 	{v18.8h, v19.8h}, [x1], #32
	ld2 	{v20.8h, v21.8h}, [x1], #32
	ld2 	{v22.8h, v23.8h}, [x1], #32
	ld2 	{v24.8h, v25.8h}, [x1], #32
	ld2 	{v26.8h, v27.8h}, [x1], #32
	ld2 	{v28.8h, v29.8h}, [x1], #32
	ld2 	{v30.8h, v31.8h}, [x1], #32

	mtobytes 16, 17, 18, 19, 5, 6, 7
	mtobytes 20, 21, 22, 23, 8, 9, 10
	mtobytes 24, 25, 26, 27, 11, 12, 13
	mtobytes 28, 29, 30, 31, 14, 15, 16

	st3		{v5.16b, v6.16b, v7.16b}, [x0], #48
	st3		{v8.16b, v9.16b, v10.16b}, [x0], #48
	st3		{v11.16b, v12.16b, v13.16b}, [x0], #48
	st3		{v14.16b, v15.16b, v16.16b}, [x0], #48

	ld2 	{v16.8h, v17.8h}, [x1], #32
	ld2 	{v18.8h, v19.8h}, [x1], #32
	ld2 	{v20.8h, v21.8h}, [x1], #32
	ld2 	{v22.8h, v23.8h}, [x1], #32
	ld2 	{v24.8h, v25.8h}, [x1], #32
	ld2 	{v26.8h, v27.8h}, [x1], #32
	ld2 	{v28.8h, v29.8h}, [x1], #32
	ld2 	{v30.8h, v31.8h}, [x1], #32

	mtobytes 16, 17, 18, 19, 5, 6, 7
	mtobytes 20, 21, 22, 23, 8, 9, 10
	mtobytes 24, 25, 26, 27, 11, 12, 13
	mtobytes 28, 29, 30, 31, 14, 15, 16

	st3		{v5.16b, v6.16b, v7.16b}, [x0], #48
	st3		{v8.16b, v9.16b, v10.16b}, [x0], #48
	st3		{v11.16b, v12.16b, v13.16b}, [x0], #48
	st3		{v14.16b, v15.16b, v16.16b}, [x0], #48

	RET
SYM_FUNC_END(kyber_poly_tobytes_armv8)

SYM_FUNC_START(kyber_poly_frombytes_armv8)
SYM_FUNC_ENTER(kyber_poly_frombytes_armv8)
.align	4
	mov w4, 0xFFF
  	mov v0.h[0], w4
  	dup v0.8h, v0.h[0]

	ld3   {v17.16b-v19.16b}, [x1], #48
	ld3   {v20.16b-v22.16b}, [x1], #48
	ld3   {v23.16b-v25.16b}, [x1], #48
	ld3   {v26.16b-v28.16b}, [x1], #48

	mfrombytes 17, 18, 19,  1,  2,  3,  4
	mfrombytes 20, 21, 22,  5,  6,  7,  8
	mfrombytes 23, 24, 25,  9, 10, 11, 12
	mfrombytes 26, 27, 28, 13, 14, 15, 16

	st2	{v1.8h, v2.8h}, [x0], #32
	st2	{v3.8h, v4.8h}, [x0], #32
	st2	{v5.8h, v6.8h}, [x0], #32
	st2	{v7.8h, v8.8h}, [x0], #32
	st2	{v9.8h, v10.8h}, [x0], #32
	st2	{v11.8h, v12.8h}, [x0], #32
	st2	{v13.8h, v14.8h}, [x0], #32
	st2	{v15.8h, v16.8h}, [x0], #32

	ld3   {v17.16b-v19.16b}, [x1], #48
	ld3   {v20.16b-v22.16b}, [x1], #48
	ld3   {v23.16b-v25.16b}, [x1], #48
	ld3   {v26.16b-v28.16b}, [x1], #48

	mfrombytes 17, 18, 19,  1,  2,  3,  4
	mfrombytes 20, 21, 22,  5,  6,  7,  8
	mfrombytes 23, 24, 25,  9, 10, 11, 12
	mfrombytes 26, 27, 28, 13, 14, 15, 16

	st2	{v1.8h, v2.8h}, [x0], #32
	st2	{v3.8h, v4.8h}, [x0], #32
	st2	{v5.8h, v6.8h}, [x0], #32
	st2	{v7.8h, v8.8h}, [x0], #32
	st2	{v9.8h, v10.8h}, [x0], #32
	st2	{v11.8h, v12.8h}, [x0], #32
	st2	{v13.8h, v14.8h}, [x0], #32
	st2	{v15.8h, v16.8h}, [x0], #32

	RET
SYM_FUNC_END(kyber_poly_frombytes_armv8)

LC_ASM_END
