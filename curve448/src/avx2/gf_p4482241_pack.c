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

#include "gf_p4482241_pack.h"

void gfp4482241pack(gfe_p4482241_16L *v, const uint8_t *u)
{
	uint8_t i, j, k, l;
	gfe_p4482241_7L t;

	for (i = 0; i < NLIMBS; ++i) {
		j = i * 8;
		t.l[i] = (uint64_t)u[j];
		l = 1;
		for (k = 1; k < 8; ++k) {
			t.l[i] |= ((uint64_t)u[j + l++] << k * 8);
		}
	}
	v->l[0] = ((t.l[0] & 0x000000000FFFFFFF));
	v->l[1] = ((t.l[0] & 0x00FFFFFFF0000000) >> 28);
	v->l[2] = ((t.l[0] & 0xFF00000000000000) >> 56) |
		  ((t.l[1] & 0x00000000000FFFFF) << 8);
	v->l[3] = ((t.l[1] & 0x0000FFFFFFF00000) >> 20);
	v->l[4] = ((t.l[1] & 0xFFFF000000000000) >> 48) |
		  ((t.l[2] & 0x0000000000000FFF) << 16);
	v->l[5] = ((t.l[2] & 0x000000FFFFFFF000) >> 12);
	v->l[6] = ((t.l[2] & 0xFFFFFF0000000000) >> 40) |
		  ((t.l[3] & 0x000000000000000F) << 24);
	v->l[7] = ((t.l[3] & 0x00000000FFFFFFF0) >> 4);
	v->l[8] = ((t.l[3] & 0x0FFFFFFF00000000) >> 32);
	v->l[9] = ((t.l[3] & 0xF000000000000000) >> 60) |
		  ((t.l[4] & 0x0000000000FFFFFF) << 4);
	v->l[10] = ((t.l[4] & 0x000FFFFFFF000000) >> 24);
	v->l[11] = ((t.l[4] & 0xFFF0000000000000) >> 52) |
		   ((t.l[5] & 0x000000000000FFFF) << 12);
	v->l[12] = ((t.l[5] & 0x00000FFFFFFF0000) >> 16);
	v->l[13] = ((t.l[5] & 0xFFFFF00000000000) >> 44) |
		   ((t.l[6] & 0x00000000000000FF) << 20);
	v->l[14] = ((t.l[6] & 0x0000000FFFFFFF00) >> 8);
	v->l[15] = ((t.l[6] & 0xFFFFFFF000000000) >> 36);
}

void gfp4482241pack167(gfe_p4482241_7L *v, const gfe_p4482241_16L *u)
{
	v->l[0] = ((u->l[0] & 0x000000000FFFFFFF)) |
		  ((u->l[1] & 0x000000000FFFFFFF) << 28) |
		  ((u->l[2] & 0x00000000000000FF) << 56);
	v->l[1] = ((u->l[2] & 0x000000000FFFFF00) >> 8) |
		  ((u->l[3] & 0x000000000FFFFFFF) << 20) |
		  ((u->l[4] & 0x000000000000FFFF) << 48);
	v->l[2] = ((u->l[4] & 0x000000000FFF0000) >> 16) |
		  ((u->l[5] & 0x000000000FFFFFFF) << 12) |
		  ((u->l[6] & 0x0000000000FFFFFF) << 40);
	v->l[3] = ((u->l[6] & 0x000000000F000000) >> 24) |
		  ((u->l[7] & 0x000000000FFFFFFF) << 4) |
		  ((u->l[8] & 0x000000000FFFFFFF) << 32) |
		  ((u->l[9] & 0x000000000000000F) << 60);
	v->l[4] = ((u->l[9] & 0x000000000FFFFFF0) >> 4) |
		  ((u->l[10] & 0x000000000FFFFFFF) << 24) |
		  ((u->l[11] & 0x0000000000000FFF) << 52);
	v->l[5] = ((u->l[11] & 0x000000000FFFF000) >> 12) |
		  ((u->l[12] & 0x000000000FFFFFFF) << 16) |
		  ((u->l[13] & 0x00000000000FFFFF) << 44);
	v->l[6] = ((u->l[13] & 0x000000000FF00000) >> 20) |
		  ((u->l[14] & 0x000000000FFFFFFF) << 8) |
		  ((u->l[15] & 0x000000000FFFFFFF) << 36);
}

void gfp4482241pack78(gfe_p4482241_8L *v, const gfe_p4482241_7L *u)
{
	v->l[0] = ((u->l[0] & 0x00FFFFFFFFFFFFFF));
	v->l[1] = ((u->l[0] & 0xFF00000000000000) >> 56) |
		  ((u->l[1] & 0x0000FFFFFFFFFFFF) << 8);
	v->l[2] = ((u->l[1] & 0xFFFF000000000000) >> 48) |
		  ((u->l[2] & 0x000000FFFFFFFFFF) << 16);
	v->l[3] = ((u->l[2] & 0xFFFFFF0000000000) >> 40) |
		  ((u->l[3] & 0x00000000FFFFFFFF) << 24);
	v->l[4] = ((u->l[3] & 0xFFFFFFFF00000000) >> 32) |
		  ((u->l[4] & 0x0000000000FFFFFF) << 32);
	v->l[5] = ((u->l[4] & 0xFFFFFFFFFF000000) >> 24) |
		  ((u->l[5] & 0x000000000000FFFF) << 40);
	v->l[6] = ((u->l[5] & 0xFFFFFFFFFFFF0000) >> 16) |
		  ((u->l[6] & 0x00000000000000FF) << 48);
	v->l[7] = ((u->l[6] & 0xFFFFFFFFFFFFFF00) >> 8);
}

void gfp4482241pack87(gfe_p4482241_7L *v, const gfe_p4482241_8L *u)
{
	v->l[0] = ((u->l[0] & 0x00FFFFFFFFFFFFFF)) |
		  ((u->l[1] & 0x00000000000000FF) << 56);
	v->l[1] = ((u->l[1] & 0x00FFFFFFFFFFFF00) >> 8) |
		  ((u->l[2] & 0x000000000000FFFF) << 48);
	v->l[2] = ((u->l[2] & 0x00FFFFFFFFFF0000) >> 16) |
		  ((u->l[3] & 0x0000000000FFFFFF) << 40);
	v->l[3] = ((u->l[3] & 0x00FFFFFFFF000000) >> 24) |
		  ((u->l[4] & 0x00000000FFFFFFFF) << 32);
	v->l[4] = ((u->l[4] & 0x00FFFFFF00000000) >> 32) |
		  ((u->l[5] & 0x000000FFFFFFFFFF) << 24);
	v->l[5] = ((u->l[5] & 0x00FFFF0000000000) >> 40) |
		  ((u->l[6] & 0x0000FFFFFFFFFFFF) << 16);
	v->l[6] = ((u->l[6] & 0x00FF000000000000) >> 48) |
		  ((u->l[7] & 0x00FFFFFFFFFFFFFF) << 8);
}

void gfp4482241unpack(uint8_t *v, const gfe_p4482241_7L *u)
{
	uint8_t i, j;
	for (i = 0; i < NLIMBS; ++i) {
		j = i * 8;
		v[j + 0] = (uint8_t)((u->l[i] & 0x00000000000000FF));
		v[j + 1] = (uint8_t)((u->l[i] & 0x000000000000FF00) >> 8);
		v[j + 2] = (uint8_t)((u->l[i] & 0x0000000000FF0000) >> 16);
		v[j + 3] = (uint8_t)((u->l[i] & 0x00000000FF000000) >> 24);
		v[j + 4] = (uint8_t)((u->l[i] & 0x000000FF00000000) >> 32);
		v[j + 5] = (uint8_t)((u->l[i] & 0x0000FF0000000000) >> 40);
		v[j + 6] = (uint8_t)((u->l[i] & 0x00FF000000000000) >> 48);
		v[j + 7] = (uint8_t)((u->l[i] & 0xFF00000000000000) >> 56);
	}
}
