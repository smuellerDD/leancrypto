/*
 * Copyright (C) 2016 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "chacha20_internal.h"
#include "chacha20_riscv64_v_zbb.h"
#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "lc_sym.h"
#include "visibility.h"

#include "asm/ARMv8/chacha20_asm_riscv64_v_zbb.h"

static void cc20_crypt_riscv64_v_zbb(struct lc_sym_state *ctx, const uint8_t *in,
			   uint8_t *out, size_t len)
{
	cc20_crypt_asm(ctx, in, out, len, ChaCha20_riscv64_v_zbb);
}

static struct lc_sym _lc_chacha20_riscv64_v_zbb = {
	.init = cc20_init,
	.setkey = cc20_setkey,
	.setiv = cc20_setiv,
	.encrypt = cc20_crypt_riscv64_v_zbb,
	.decrypt = cc20_crypt_riscv64_v_zbb,
	.statesize = LC_CC20_BLOCK_SIZE,
	.blocksize = 1,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_chacha20_riscv64_v_zbb) =
	&_lc_chacha20_riscv64_v_zbb;
