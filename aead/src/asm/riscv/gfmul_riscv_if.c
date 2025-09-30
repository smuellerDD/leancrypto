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

#include "cpufeatures.h"
#include "gfmul_riscv.h"
#include "ext_headers_arm.h"

void gcm_init_rv64i_zbc(uint64_t *Htable, const uint64_t Xi[2]);
void gcm_init_rv64i_zbc__zbb(uint64_t *Htable, const uint64_t Xi[2]);
void gcm_init_rv64i_zbc__zbkb(uint64_t *Htable, const uint64_t Xi[2]);
void gcm_gmult_rv64i_zbc(uint64_t Xi[2], const uint64_t *Htable);
void gcm_gmult_rv64i_zbc__zbkb(uint64_t Xi[2], const uint64_t *Htable);

void gfmul_init_riscv64(uint64_t *Htable, const uint64_t Xi[2])
{
	gcm_init_rv64i_zbc(Htable, Xi);
}

void gfmul_init_riscv64_zbb(uint64_t *Htable, const uint64_t Xi[2])
{
	gcm_init_rv64i_zbc__zbb(Htable, Xi);
}

void gfmul_riscv64(uint64_t Xi[2], const uint64_t *Htable)
{
	gcm_gmult_rv64i_zbc(Xi, Htable);
}
