
/* CORE MACROS */

/*************************************************	
*	Macro Name:		mbarret
*	Description:	Vectorized Barrett Reduction
*	Arguments:		a as va.8h = [a0, a1, ..., a7], 
*								vq.8h = [q, -, v, ...]
*	Intermediate Values/Vectors:
*								v10 as vd
**************************************************/
.macro mbarret a
	sqdmulh 	v10.8h, v\a\().8h, v15.h[2]   	// v10 = (2 * a * const v)_HI
	sshr 		v10.8h, v10.8h, 11				// t: v10 <- v10 >> 11 (right shift)
	mls			v\a\().8h, v10.8h, v15.h[0]		// a <- a - q * t
.endm

/*************************************************	
*	Macro Name:		mtomont
*	Description:	Vectorized conversion of polynomial coefficients from normal
*					domain to Montgomery domain
*	Arguments:		a as va.8h = [a0, a1, ..., a7], 
*					vq.8h = [q, q0, ...]
*	Intermediate Values/Vectors:
*					v10, v11, v12, v13
**************************************************/
.macro mtomont a
	mul			v10.8h, v\a\().8h, v15.h[2]		// af_LO = (a * f)_LO
	sqdmulh     v11.8h, v\a\().8h, v15.h[2]		// 2af_HI = (2 * a * f)_HI
	mul			v12.8h, v10.8h, v15.h[1]       	// qiaf_L = (QINV * af_LO)_LO 
	sqdmulh     v13.8h, v12.8h, v15.h[0]		// 2t = (2 * Q * qiaf_L)_HI
	shsub		v\a\().8h, v11.8h, v13.8h		// a = (2af_HI - 2t) / 2 = af_HI - t 
.endm

/*************************************************	
*	Macro Name:		fqmul
*	Description:	Multiplication followed by Montgomery Reduction
*					i.e. c = (a*b)*R^(-1) mod q
*	Arguments:		va.8h = [a0, a1, ..., a7], 
*					vb.8h = [b0, b1, ..., b7],
*					vq.8h = [q, q0, ...],
*					vc.8h = [c0, c1, ..., c7]
*	Intermediate Values/Vectors:
*					v10 as vd, 
*					v11 as ve,
*					v12 as vf,
*					v13 as vg,
**************************************************/
.macro fqmul c, a, b
  sqdmulh   v10.8h, v\a\().8h, v\b\().8h    // 2ab_H = (2 * a * b)_HI
  mul 		v11.8h, v\a\().8h, v\b\().8h    // ab_L = (a * b)_LO
  mul 		v12.8h, v11.8h, v15.h[1]      	// qiab_L = (QINV * ab_L)_LO
  sqdmulh   v13.8h, v12.8h, v15.h[0]  		// 2u = (2 * Q * qiab_L)_HI
  shsub 	v\c\().8h, v10.8h, v13.8h     	// t = (2ab_H - 2u) / 2 = ab_H - u 
.endm





/* REDUCTION GROUPINGS */

/*************************************************	
*	Macro Name:		mbarret16
*	Description:	Apply Barrett Reduction to 16 vectors
*	Arguments:		Vector numbers a0 ... a15 
*					(not vector 15 which is reserved for constants) 
**************************************************/
.macro mbarret16 a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15
	// load constants for Barrett Reduction
	mov w4, 3329
	mov v15.h[0], w4		// v15.s[0] = q = 3329 = 0D01
	mov w4, 20159
	mov v15.h[2], w4 		// v15.s[2] = v = 20159 used in Barrets reduction
	// Barrett Reduction
	mbarret \a0
	mbarret \a1
	mbarret \a2
	mbarret \a3
	mbarret \a4
	mbarret \a5
	mbarret \a6
	mbarret \a7
	mbarret \a8
	mbarret \a9
	mbarret \a10
	mbarret \a11
	mbarret \a12
	mbarret \a13
	mbarret \a14
	mbarret \a15
.endm



/* Shuffle Ops */
// Old Ax = Ax0 Ax1, Bx = Bx0 Bx1
// New Ax = Ax0 Bx0, Bx = Ax1 Bx1
.macro shuffle4 A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7
	trn1	v8.2d, v\A0\().2d, v\B0\().2d
	trn2	v9.2d, v\A0\().2d, v\B0\().2d

	trn1	v\A0\().2d, v\A1\().2d, v\B1\().2d
	trn2	v\B0\().2d, v\A1\().2d, v\B1\().2d

	trn1	v\A1\().2d, v\A2\().2d, v\B2\().2d
	trn2	v\B1\().2d, v\A2\().2d, v\B2\().2d

	trn1	v\A2\().2d, v\A3\().2d, v\B3\().2d
	trn2	v\B2\().2d, v\A3\().2d, v\B3\().2d

	trn1	v\A3\().2d, v\A4\().2d, v\B4\().2d
	trn2	v\B3\().2d, v\A4\().2d, v\B4\().2d

	trn1	v\A4\().2d, v\A5\().2d, v\B5\().2d
	trn2	v\B4\().2d, v\A5\().2d, v\B5\().2d

	trn1	v\A5\().2d, v\A6\().2d, v\B6\().2d
	trn2	v\B5\().2d, v\A6\().2d, v\B6\().2d

	trn1	v\A6\().2d, v\A7\().2d, v\B7\().2d
	trn2	v\B6\().2d, v\A7\().2d, v\B7\().2d

	mov   v\A7\().16b, v8.16b
	mov   v\B7\().16b, v9.16b
.endm

// Old Ax = Ax0 Ax1 Ax2 Ax3, Bx = Bx0 Bx1 Bx2 Bx3
// New Ax = Ax0 Bx0 Ax2 Bx2, Bx = Ax1 Bx1 Ax3 Bx3
.macro shuffle2 A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7
	trn1	v8.4s, v\A0\().4s, v\B0\().4s
	trn2	v9.4s, v\A0\().4s, v\B0\().4s

	trn1	v\A0\().4s, v\A1\().4s, v\B1\().4s
	trn2	v\B0\().4s, v\A1\().4s, v\B1\().4s

	trn1	v\A1\().4s, v\A2\().4s, v\B2\().4s
	trn2	v\B1\().4s, v\A2\().4s, v\B2\().4s

	trn1	v\A2\().4s, v\A3\().4s, v\B3\().4s
	trn2	v\B2\().4s, v\A3\().4s, v\B3\().4s

	trn1	v\A3\().4s, v\A4\().4s, v\B4\().4s
	trn2	v\B3\().4s, v\A4\().4s, v\B4\().4s

	trn1	v\A4\().4s, v\A5\().4s, v\B5\().4s
	trn2	v\B4\().4s, v\A5\().4s, v\B5\().4s

	trn1	v\A5\().4s, v\A6\().4s, v\B6\().4s
	trn2	v\B5\().4s, v\A6\().4s, v\B6\().4s

	trn1	v\A6\().4s, v\A7\().4s, v\B7\().4s
	trn2	v\B6\().4s, v\A7\().4s, v\B7\().4s

	mov   v\A7\().16b, v8.16b
	mov   v\B7\().16b, v9.16b
.endm
