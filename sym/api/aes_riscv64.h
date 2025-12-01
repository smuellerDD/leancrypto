/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef AES_RISCV64_V8_H
#define AES_RISCV64_V8_H

#ifdef __cplusplus
extern "C" {
#endif

extern const struct lc_sym *lc_aes_cbc_riscv64;
extern const struct lc_sym *lc_aes_ctr_riscv64;
extern const struct lc_sym *lc_aes_kw_riscv64;
extern const struct lc_sym *lc_aes_riscv64;
extern const struct lc_sym *lc_aes_riscv64_enc_only;
extern const struct lc_sym *lc_aes_xts_riscv64;

/* Maximum size of the AES context */
#define LC_AES_RISCV64_MAX_BLOCK_SIZE (244 * 2)
#define LC_AES_RISCV64_XTS_MAX_BLOCK_SIZE (244 * 3 + 48)
#define LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE (244 * 2 + 48)

#ifdef __cplusplus
}
#endif

#endif /* AES_RISCV64_V8_H */
