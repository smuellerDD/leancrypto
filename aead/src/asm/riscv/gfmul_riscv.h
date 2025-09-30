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

#ifndef GFMUL_RISCV_H
#define GFMUL_RISCV_H

#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_HOST_RISCV64

void gfmul_init_riscv64(uint64_t *Htable, const uint64_t Xi[2]);
void gfmul_init_riscv64_zbb(uint64_t *Htable, const uint64_t Xi[2]);
void gfmul_riscv64(uint64_t Xi[2], const uint64_t *Htable);

#else
static inline void gfmul_init_riscv64(uint64_t *Htable, const uint64_t Xi[2])
{
	(void)Htable;
	(void)Xi;
}

static inline void gfmul_init_riscv64_zbb(uint64_t *Htable,
					  const uint64_t Xi[2])
{
	(void)Htable;
	(void)Xi;
}

static inline void gfmul_riscv64(uint64_t Xi[2], const uint64_t *Htable)
{
	(void)Xi;
	(void)Htable;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* GFMUL_RISCV_H */
