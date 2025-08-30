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

#ifndef GFMUL_X86_64_H
#define GFMUL_X86_64_H

#include "lc_aes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_HOST_X86_64

void gfmu_x8664(uint64_t a[2], const uint64_t *Htable);
void gfmu_x8664_init(uint64_t *Htable, const uint64_t H[2]);

#else /* LC_HOST_X86_64 */

static inline void gfmu_x8664(uint64_t a[2], const uint64_t *Htable)
{
	(void)a;
	(void)Htable;
}

static inline void gfmu_x8664_init(uint64_t *Htable, const uint64_t H[2])
{
	(void)Htable;
	(void)H;
}

#endif /* LC_HOST_X86_64 */

#ifdef __cplusplus
}
#endif

#endif /* GFMUL_X86_64_H */
