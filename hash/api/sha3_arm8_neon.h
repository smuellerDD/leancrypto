/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef SHA3_ARM8_NEON
#define SHA3_ARM8_NEON

#ifdef __cplusplus
extern "C"
{
#endif

extern const struct lc_hash *lc_sha3_224_arm8_neon;
extern const struct lc_hash *lc_sha3_256_arm8_neon;
extern const struct lc_hash *lc_sha3_384_arm8_neon;
extern const struct lc_hash *lc_sha3_512_arm8_neon;

extern const struct lc_hash *lc_shake128_arm8_neon;
extern const struct lc_hash *lc_shake256_arm8_neon;
extern const struct lc_hash *lc_cshake128_arm8_neon;
extern const struct lc_hash *lc_cshake256_arm8_neon;

#ifdef __cplusplus
}
#endif

#endif /* SHA3_ARM8_NEON */
