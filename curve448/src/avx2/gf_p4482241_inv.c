/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from
+-----------------------------------------------------------------------------+
| This code corresponds to the the paper "Efficient 4-way Vectorizations of   |
| the Montgomery Ladder" authored by   			       	       	      |
| Kaushik Nath,  Indian Statistical Institute, Kolkata, India, and            |
| Palash Sarkar, Indian Statistical Institute, Kolkata, India.	              |
+-----------------------------------------------------------------------------+
| Copyright (c) 2020, Kaushik Nath and Palash Sarkar.                         |
|                                                                             |
| Permission to use this code is granted.                          	      |
|                                                                             |
| Redistribution and use in source and binary forms, with or without          |
| modification, are permitted provided that the following conditions are      |
| met:                                                                        |
|                                                                             |
| * Redistributions of source code must retain the above copyright notice,    |
|   this list of conditions and the following disclaimer.                     |
|                                                                             |
| * Redistributions in binary form must reproduce the above copyright         |
|   notice, this list of conditions and the following disclaimer in the       |
|   documentation and/or other materials provided with the distribution.      |
|                                                                             |
| * The names of the contributors may not be used to endorse or promote       |
|   products derived from this software without specific prior written        |
|   permission.                                                               |
+-----------------------------------------------------------------------------+
| THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY EXPRESS OR       |
| IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES   |
| OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.     |
| IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,      |
| INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT    |
| NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   |
| DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY       |
| THEORY LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING |
| NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,| 
| EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                          |
+-----------------------------------------------------------------------------+
*/

#include "ext_headers_internal.h"
#include "gf_p4482241_type.h"
#include "gf_p4482241_arith.h"

void gfp4482241invx(gfe_p4482241_7L *einv, const gfe_p4482241_7L *e)
{
	gfe_p4482241_7L t, t2_3_0, t2_9_0, t2_18_0, t2_37_0, t2_111_0, t2_223_0,
		t2_224_2;

	/* 2 */ gfp4482241sqrx(&t, e);
	/* 3 */ gfp4482241mulx(&t, &t, e);
	/* 6 */ gfp4482241sqrx(&t, &t);
	/* 2^3 - 1      */ gfp4482241mulx(&t2_3_0, &t, e);

	/* 2^6 - 2^3    */ gfp4482241nsqrx(&t, &t2_3_0, 3);
	/* 2^6 - 1      */ gfp4482241mulx(&t, &t, &t2_3_0);

	/* 2^9 - 2^3    */ gfp4482241nsqrx(&t, &t, 3);
	/* 2^9 - 1      */ gfp4482241mulx(&t2_9_0, &t, &t2_3_0);

	/* 2^18 - 2^9   */ gfp4482241nsqrx(&t, &t2_9_0, 9);
	/* 2^18 - 1     */ gfp4482241mulx(&t2_18_0, &t, &t2_9_0);

	/* 2^19 - 2     */ gfp4482241sqrx(&t, &t2_18_0);
	/* 2^19 - 1     */ gfp4482241mulx(&t, &t, e);

	/* 2^37 - 2^18  */ gfp4482241nsqrx(&t, &t, 18);
	/* 2^37 - 1     */ gfp4482241mulx(&t2_37_0, &t, &t2_18_0);

	/* 2^74 - 2^37  */ gfp4482241nsqrx(&t, &t2_37_0, 37);
	/* 2^74 - 1     */ gfp4482241mulx(&t, &t, &t2_37_0);

	/* 2^111 - 2^37 */ gfp4482241nsqrx(&t, &t, 37);
	/* 2^111 - 1    */ gfp4482241mulx(&t2_111_0, &t, &t2_37_0);

	/* 2^222 - 2^111*/ gfp4482241nsqrx(&t, &t2_111_0, 111);
	/* 2^222 - 1    */ gfp4482241mulx(&t, &t, &t2_111_0);

	/* 2^223 - 2    */ gfp4482241sqrx(&t, &t);
	/* 2^223 - 1    */ gfp4482241mulx(&t2_223_0, &t, e);

	/* 2^224 - 4    */ gfp4482241sqrx(&t2_224_2, &t);

	/* 2^448 - 2^225*/ gfp4482241nsqrx(&t, &t2_223_0, 225);

	/* 2^448 - 2^224 - 4 */ gfp4482241mulx(&t, &t, &t2_224_2);
	/* 2^448 - 2^224 - 3 */ gfp4482241mulx(einv, &t, e);
}

void gfp4482241inv(gfe_p4482241_8L *einv, const gfe_p4482241_8L *e)
{
	gfe_p4482241_8L t, t2_3_0, t2_9_0, t2_18_0, t2_37_0, t2_111_0, t2_223_0,
		t2_224_2;

	/* 2 */ gfp4482241sqr(&t, e);
	/* 3 */ gfp4482241mul(&t, &t, e);
	/* 6 */ gfp4482241sqr(&t, &t);
	/* 2^3 - 1      */ gfp4482241mul(&t2_3_0, &t, e);

	/* 2^6 - 2^3    */ gfp4482241nsqr(&t, &t2_3_0, 3);
	/* 2^6 - 1      */ gfp4482241mul(&t, &t, &t2_3_0);

	/* 2^9 - 2^3    */ gfp4482241nsqr(&t, &t, 3);
	/* 2^9 - 1      */ gfp4482241mul(&t2_9_0, &t, &t2_3_0);

	/* 2^18 - 2^9   */ gfp4482241nsqr(&t, &t2_9_0, 9);
	/* 2^18 - 1     */ gfp4482241mul(&t2_18_0, &t, &t2_9_0);

	/* 2^19 - 2     */ gfp4482241sqr(&t, &t2_18_0);
	/* 2^19 - 1     */ gfp4482241mul(&t, &t, e);

	/* 2^37 - 2^18  */ gfp4482241nsqr(&t, &t, 18);
	/* 2^37 - 1     */ gfp4482241mul(&t2_37_0, &t, &t2_18_0);

	/* 2^74 - 2^37  */ gfp4482241nsqr(&t, &t2_37_0, 37);
	/* 2^74 - 1     */ gfp4482241mul(&t, &t, &t2_37_0);

	/* 2^111 - 2^37 */ gfp4482241nsqr(&t, &t, 37);
	/* 2^111 - 1    */ gfp4482241mul(&t2_111_0, &t, &t2_37_0);

	/* 2^222 - 2^111*/ gfp4482241nsqr(&t, &t2_111_0, 111);
	/* 2^222 - 1    */ gfp4482241mul(&t, &t, &t2_111_0);

	/* 2^223 - 2    */ gfp4482241sqr(&t, &t);
	/* 2^223 - 1    */ gfp4482241mul(&t2_223_0, &t, e);

	/* 2^224 - 4    */ gfp4482241sqr(&t2_224_2, &t);

	/* 2^448 - 2^225*/ gfp4482241nsqr(&t, &t2_223_0, 225);

	/* 2^448 - 2^224 - 4 */ gfp4482241mul(&t, &t, &t2_224_2);
	/* 2^448 - 2^224 - 3 */ gfp4482241mul(einv, &t, e);
}
