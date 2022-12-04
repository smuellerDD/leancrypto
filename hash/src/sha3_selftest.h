/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef SHA3_SELFTEST_H
#define SHA3_SELFTEST_H

#include "lc_hash.h"

#ifdef __cplusplus
extern "C"
{
#endif

void sha3_224_selftest_common(const struct lc_hash *sha3_224,
			      int *tested, const char *impl);
void sha3_256_selftest_common(const struct lc_hash *sha3_256,
			      int *tested, const char *impl);
void sha3_384_selftest_common(const struct lc_hash *sha3_384,
			      int *tested, const char *impl);
void sha3_512_selftest_common(const struct lc_hash *sha3_512,
			      int *tested, const char *impl);
void shake128_selftest_common(const struct lc_hash *shake128,
			      int *tested, const char *impl);
void shake256_selftest_common(const struct lc_hash *shake256,
			      int *tested, const char *impl);
void cshake128_selftest_common(const struct lc_hash *cshake128,
			       int *tested, const char *impl);
void cshake256_selftest_common(const struct lc_hash *cshake256,
			       int *tested, const char *impl);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_SELFTEST_H */
